import "@atcute/ozone/lexicons";
import { XRPCError } from "@atcute/client";
import type {
	At,
	ComAtprotoLabelQueryLabels,
	ToolsOzoneModerationEmitEvent,
} from "@atcute/client/lexicons";
import type { FastifyBaseLogger } from "fastify";
import { parsePrivateKey, verifyJwt } from "./util/crypto.js";
import { formatLabel, labelIsSigned, signLabel } from "./util/labels.js";
import type {
	CreateLabelData,
	SavedLabel,
	SignedLabel,
	UnsignedLabel,
} from "./util/types.js";
import { excludeNullish, frameToBytes } from "./util/util.js";
import { DbProvider, DefaultDbProvider } from "./db-provider.js";
import { Context, Hono, HonoRequest } from 'hono';
import { NodeWebSocket } from '@hono/node-ws';
import { WSContext, WSEvents } from "hono/ws";

const INVALID_SIGNING_KEY_ERROR = `Make sure to provide a private signing key, not a public key.

If you don't have a key, generate and set one using the \`npx @skyware/labeler setup\` command or the \`import { plcSetupLabeler } from "@skyware/labeler/scripts"\` function.
For more information, see https://skyware.js.org/guides/labeler/introduction/getting-started/`;

/**
 * Options for the {@link LabelerServer} class.
 */
export interface LabelerOptions {
	/** The DID of the labeler account. */
	did: string;

	/**
	 * The private signing key used for the labeler.
	 * If you don't have a key, generate and set one using {@link plcSetupLabeler}.
	 */
	signingKey: string;

	/**
	 * A function that returns whether a DID is authorized to create labels.
	 * By default, only the labeler account is authorized.
	 * @param did The DID to check.
	 */
	auth?: (did: string) => boolean | Promise<boolean>;

	/**
	 * The path to the SQLite `.db` database file.
	 * @default labels.db
	 */
	dbPath?: string;

	db?: DbProvider;
}

export class LabelerServer {
	/** The Fastify application instance. */
	app: Hono;

	db: DbProvider;

	/** The DID of the labeler account. */
	did: At.DID;

	/** A function that returns whether a DID is authorized to create labels. */
	private auth: (did: string) => boolean | Promise<boolean>;

	/** Open WebSocket connections, mapped by request NSID. */
	private connections = new Map<string, Set<WSContext>>();

	/** The signing key used for the labeler. */
	private signingKey: Uint8Array;

	/**
	 * Create a labeler server.
	 * @param options Configuration options.
	 * @private
	 */
	constructor(app: Hono, upgradeWebSocket: NodeWebSocket['upgradeWebSocket'], options: LabelerOptions, private readonly logger: FastifyBaseLogger) {
		this.did = options.did as At.DID;
		this.auth = options.auth ?? ((did) => did === this.did);

		try {
			if (options.signingKey.startsWith("did:key:")) throw 0;
			this.signingKey = parsePrivateKey(options.signingKey);
			if (this.signingKey.byteLength !== 32) throw 0;
		} catch {
			throw new Error(INVALID_SIGNING_KEY_ERROR);
		}

		this.db = options.db ?? new DefaultDbProvider(options.dbPath);

		this.app = app;
        
        app.get("/xrpc/com.atproto.label.queryLabels", this.queryLabelsHandler);
        app.post("/xrpc/tools.ozone.moderation.emitEvent", this.emitEventHandler);
        app.get(
            "/xrpc/com.atproto.label.subscribeLabels",
            upgradeWebSocket(this.subscribeLabelsHandler)
        );
        app.get("/xrpc/_health", this.healthHandler);
	}
    
	async queryLabels(identifier: string, cursor = 0, limit = 1): Promise<SavedLabel[]> {
		return await this.db.queryLabels(identifier, cursor, limit);
	}

	/**
	 * Insert a label into the database, emitting it to subscribers.
	 * @param label The label to insert.
	 * @returns The inserted label.
	 */
	private async saveLabel(label: UnsignedLabel): Promise<SavedLabel> {
		const signed = labelIsSigned(label) ? label : signLabel(label, this.signingKey);

		const id = await this.db.saveLabel(signed);

		this.emitLabel(id, signed);
		return { id, ...signed };
	}

	/**
	 * Create and insert a label into the database, emitting it to subscribers.
	 * @param label The label to create.
	 * @returns The created label.
	 */
	async createLabel(label: CreateLabelData): Promise<SavedLabel> {
		return await this.saveLabel(
			excludeNullish({
				...label,
				src: (label.src ?? this.did) as At.DID,
				cts: label.cts ?? new Date().toISOString(),
			}),
		);
	}

	/**
	 * Create and insert labels into the database, emitting them to subscribers.
	 * @param subject The subject of the labels.
	 * @param labels The labels to create.
	 * @returns The created labels.
	 */
	async createLabels(
		subject: { uri: string; cid?: string | undefined },
		labels: { create?: string[]; negate?: string[] },
	): Promise<SavedLabel[]> {
		const { uri, cid } = subject;
		const { create, negate } = labels;

		const createdLabels: Array<SavedLabel> = [];
		if (create) {
			for (const val of create) {
				const created = await this.createLabel({ uri, cid, val });
				createdLabels.push(created);
			}
		}
		if (negate) {
			for (const val of negate) {
				const negated = await this.createLabel({ uri, cid, val, neg: true });
				createdLabels.push(negated);
			}
		}
		return createdLabels;
	}

	/**
	 * Emit a label to all subscribers.
	 * @param seq The label's id.
	 * @param label The label to emit.
	 */
	private emitLabel(seq: number | string, label: SignedLabel) {
		const bytes = frameToBytes("message", { seq, labels: [formatLabel(label)] }, "#labels");
		this.connections.get("com.atproto.label.subscribeLabels")?.forEach((ws) => {
			ws.send(bytes);
		});
	}

	/**
	 * Parse a user DID from an Authorization header JWT.
	 * @param req The Express request object.
	 */
	private async parseAuthHeaderDid(req: HonoRequest): Promise<string> {
		const authHeader = req.header('authorization');
		if (!authHeader) {
			throw new XRPCError(401, {
				kind: "AuthRequired",
				description: "Authorization header is required",
			});
		}

		const [type, token] = authHeader.split(" ");
		if (type !== "Bearer" || !token) {
			throw new XRPCError(400, {
				kind: "MissingJwt",
				description: "Missing or invalid bearer token",
			});
		}

		const nsid = (req.url || "").split("?")[0].replace("/xrpc/", "").replace(
			/\/$/,
			"",
		);

		const payload = await verifyJwt(token, this.did, nsid);

		return payload.iss;
	}

    subscribeLabelsHandler = (c: Context): WSEvents => {
        const cursor = parseInt(c.req.query('cursor') ?? 'NaN', 10);

        return {
            onOpen: async (evt, ws) => {
                // catch up:
                if (cursor !== undefined) {

                    if (await this.db.isCursorInTheFuture(cursor)) {
                        this.logger.warn(`sending FutureCursor to ws`);

                        const errorBytes = frameToBytes("error", {
                            error: "FutureCursor",
                            message: "Cursor is in the future",
                        });
                        ws.send(errorBytes);
                        ws.close();
                        return;
                    }
                        
                    try {
                        for await (const { id: seq, ...label } of this.db.iterateLabels(cursor)) {
                            this.logger.debug(`sending label ${seq} (${label.val}) to ws`);

                            const bytes = frameToBytes(
                                "message",
                                { seq, labels: [formatLabel(label)] },
                                "#labels",
                            );
                            ws.send(bytes);
                        }
                    } catch (e) {
                        this.logger.error(e);
                        const errorBytes = frameToBytes("error", {
                            error: "InternalServerError",
                            message: "An unknown error occurred",
                        });
                        ws.send(errorBytes);
                        ws.close();
                        return;
                    }
                }

                this.addSubscription("com.atproto.label.subscribeLabels", ws);
                this.logger.info('added subscription');
            },
            onError: (evt) => {
                this.logger.error(evt, `ws error`);
            },
            onClose: (evt, ws) => {
                this.logger.debug(evt, `ws closed!!!`);
                this.removeSubscription("com.atproto.label.subscribeLabels", ws);
            },
        } satisfies WSEvents;
    }

	/**
	 * Handler for [com.atproto.label.queryLabels](https://github.com/bluesky-social/atproto/blob/main/lexicons/com/atproto/label/queryLabels.json).
	 */
	queryLabelsHandler = async (c: Context) => {
		const uriPatterns = c.req.queries('uriPatterns') || [];

		const sources = c.req.queries('sources') || [];

		const cursor = parseInt(c.req.query('cursor') ?? '0', 10);
		if (cursor !== undefined && Number.isNaN(cursor)) {
			throw new XRPCError(400, {
				kind: "InvalidRequest",
				description: "Cursor must be an integer",
			});
		}

		const limit = parseInt(`${c.req.query('limit') || 50}`, 10);
		if (Number.isNaN(limit) || limit < 1 || limit > 250) {
			throw new XRPCError(400, {
				kind: "InvalidRequest",
				description: "Limit must be an integer between 1 and 250",
			});
		}

		const rows = await this.db.searchLabels(cursor, limit, uriPatterns, sources);

		const labels = rows.map(formatLabel);

		const nextCursor = rows[rows.length - 1]?.id?.toString(10) || "0";

		return c.json({ cursor: nextCursor, labels } satisfies ComAtprotoLabelQueryLabels.Output);
	};

	/**
	 * Handler for [tools.ozone.moderation.emitEvent](https://github.com/bluesky-social/atproto/blob/main/lexicons/tools/ozone/moderation/emitEvent.json).
	 */
	emitEventHandler = async (c: Context) => {
		const actorDid = await this.parseAuthHeaderDid(c.req);
		const authed = await this.auth(actorDid);
		if (!authed) {
			throw new XRPCError(401, { kind: "AuthRequired", description: "Unauthorized" });
		}

		const { event, subject, subjectBlobCids = [], createdBy } = await c.req.json();
		if (!event || !subject || !createdBy) {
			throw new XRPCError(400, {
				kind: "InvalidRequest",
				description: "Missing required field(s)",
			});
		}

		if (event.$type !== "tools.ozone.moderation.defs#modEventLabel") {
			throw new XRPCError(400, {
				kind: "InvalidRequest",
				description: "Unsupported event type",
			});
		}

		if (!event.createLabelVals?.length && !event.negateLabelVals?.length) {
			throw new XRPCError(400, {
				kind: "InvalidRequest",
				description: "Must provide at least one label value",
			});
		}

		const uri = subject.$type === "com.atproto.admin.defs#repoRef"
			? subject.did
			: subject.$type === "com.atproto.repo.strongRef"
			? subject.uri
			: null;
		const cid = subject.$type === "com.atproto.repo.strongRef" ? subject.cid : undefined;

		if (!uri) {
			throw new XRPCError(400, { kind: "InvalidRequest", description: "Invalid subject" });
		}

		const labels = await this.createLabels({ uri, cid }, {
			create: event.createLabelVals,
			negate: event.negateLabelVals,
		});

		if (!labels.length || !labels[0]?.id) {
			throw new Error(`No labels were created\nEvent:\n${JSON.stringify(event, null, 2)}`);
		}

		return c.json(
			{
				id: labels[0].id,
				event,
				subject,
				subjectBlobCids,
				createdBy,
				createdAt: new Date().toISOString(),
			} satisfies ToolsOzoneModerationEmitEvent.Output,
		);
	};

	/**
	 * Handler for the health check endpoint.
	 */
	healthHandler = (c: Context) => {
		const VERSION = "0.2.0";
		return c.json({ version: VERSION });
	};

	/**
	 * Catch-all handler for unknown XRPC methods.
	 */
	unknownMethodHandler = (c: Context) =>
		c.json({ error: "MethodNotImplemented", message: "Method Not Implemented" }, 501);

	/**
	 * Default error handler.
	 */
	// errorHandler: typeof this.app.errorHandler = async (err, _req, res) => {
	// 	if (err instanceof XRPCError) {
	// 		return res.status(err.status).send({ error: err.kind, message: err.description });
	// 	} else {
	// 		console.error(err);
	// 		return res.status(500).send({
	// 			error: "InternalServerError",
	// 			message: "An unknown error occurred",
	// 		});
	// 	}
	// };

	/**
	 * Add a WebSocket connection to the list of subscribers for a given lexicon.
	 * @param nsid The NSID of the lexicon to subscribe to.
	 * @param ws The WebSocket connection to add.
	 */
	private addSubscription(nsid: string, ws: WSContext) {
		const subs = this.connections.get(nsid) ?? new Set();
		subs.add(ws);
		this.connections.set(nsid, subs);
	}

	/**
	 * Remove a WebSocket connection from the list of subscribers for a given lexicon.
	 * @param nsid The NSID of the lexicon to unsubscribe from.
	 * @param ws The WebSocket connection to remove.
	 */
	private removeSubscription(nsid: string, ws: WSContext) {
		const subs = this.connections.get(nsid);
		if (subs) {
			subs.delete(ws);
			if (!subs.size) this.connections.delete(nsid);
		}
	}
}
