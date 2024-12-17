import { At, ComAtprotoLabelDefs } from "@atcute/client/lexicons";
import type { WebsocketHandler } from "@fastify/websocket";
import type {
	RawReplyDefaultExpression,
	RawRequestDefaultExpression,
	RawServerDefault,
	RequestGenericInterface,
	RouteGenericInterface,
	RouteHandlerMethod,
} from "fastify";

type NullishKeys<T> = {
	[K in keyof T]: null extends T[K] ? K : undefined extends T[K] ? K : never;
}[keyof T];
type NonNullishKeys<T> = Exclude<keyof T, NullishKeys<T>>;
export type NonNullishPartial<T> =
	& { [K in NullishKeys<T>]+?: Exclude<T[K], null | undefined> }
	& { [K in NonNullishKeys<T>]-?: T[K] };

/**
 * Data required to create a label.
 */
export interface CreateLabelData {
	/** The label value. */
	val: string;
	/** The subject of the label. If labeling an account, this should be a string beginning with `did:`. */
	uri: string;
	/** Optionally, a CID specifying the version of `uri` to label. */
	cid?: string | null | undefined;
	/** Whether this label is negating a previous instance of this label applied to the same subject. */
	neg?: boolean | null | undefined;
	/** The DID of the actor who created this label, if different from the labeler. */
	src?: string | null | undefined;
	/** The creation date of the label. Must be in ISO 8601 format. */
	cts?: string | null | undefined;
	/** The expiration date of the label, if any. Must be in ISO 8601 format. */
	exp?: string | null | undefined;
}

export type UnsignedLabel = {
    /** Timestamp when this label was created. */
    cts: string;
    /** DID of the actor who created this label. */
    src: At.DID;
    /** AT URI of the record, repository (account), or other resource that this label applies to. */
    uri: string;
    /**
     * The short string name of the value or type of this label. \
     * Maximum string length: 128
     */
    val: string;
    /** Optionally, CID specifying the specific version of 'uri' resource this label applies to. */
    cid?: At.CID | null;
    /** Timestamp at which this label expires (no longer applies). */
    exp?: string | null;
    /** If true, this is a negation label, overwriting a previous label. */
    neg?: boolean | null;
    /** The AT Protocol version of the label object. */
    ver?: number | null;
};
export type SignedLabel = UnsignedLabel & { sig: Uint8Array };
export type FormattedLabel = UnsignedLabel & { sig?: At.Bytes };
export type SavedLabel = SignedLabel & { id: number };

export type QueryHandler<
	T extends RouteGenericInterface["Querystring"] = RouteGenericInterface["Querystring"],
> = RouteHandlerMethod<
	RawServerDefault,
	RawRequestDefaultExpression,
	RawReplyDefaultExpression,
	{ Querystring: T }
>;
export type ProcedureHandler<
	T extends RouteGenericInterface["Body"] = RouteGenericInterface["Body"],
> = RouteHandlerMethod<
	RawServerDefault,
	RawRequestDefaultExpression,
	RawReplyDefaultExpression,
	{ Body: T }
>;
export type SubscriptionHandler<
	T extends RequestGenericInterface["Querystring"] = RequestGenericInterface["Querystring"],
> = WebsocketHandler<RawServerDefault, RawRequestDefaultExpression, { Querystring: T }>;
