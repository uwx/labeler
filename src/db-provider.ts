import Database, { type Database as SQLiteDatabase } from "libsql";
import { SavedLabel, SignedLabel } from "./index.js";
import { XRPCError } from "@atcute/client";

export interface DbProvider {
    queryLabels(identifier: string, cursor?: number, limit?: number): Promise<SavedLabel[]> | SavedLabel[];
    saveLabel(label: SignedLabel): number | Promise<number>;
    searchLabels(cursor?: number, limit?: number, uriPatterns?: string[], sources?: string[]): Promise<SavedLabel[]> | SavedLabel[];

    isCursorInTheFuture(cursor: number): boolean | Promise<boolean>;
    iterateLabels(cursor?: number): Iterable<SavedLabel> | AsyncIterable<SavedLabel>;
}

/** @private */
export class DefaultDbProvider implements DbProvider {
    private db: SQLiteDatabase;

    constructor(dbPath?: string) {
		this.db = new Database(dbPath ?? "labels.db");
		this.db.pragma("journal_mode = WAL");
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS labels (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				src TEXT NOT NULL,
				uri TEXT NOT NULL,
				cid TEXT,
				val TEXT NOT NULL,
				neg BOOLEAN DEFAULT FALSE,
				cts DATETIME NOT NULL,
				exp DATETIME,
				sig BLOB
			);
		`);
    }

    queryLabels(identifier: string, cursor = 0, limit = 1): SavedLabel[] {
		const stmt = this.db.prepare(`
			SELECT id, src, uri, cid, val, neg, cts, exp, sig
				FROM labels
				WHERE val = ? AND id > ?
				ORDER BY id ASC
				LIMIT ?
		`);

		const result = stmt.all(identifier, cursor, limit);
		return result as SavedLabel[];
    }

    saveLabel(label: SignedLabel): number {
		const stmt = this.db.prepare(`
			INSERT INTO labels (src, uri, cid, val, neg, cts, exp, sig)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`);

		const { src, uri, cid, val, neg, cts, exp, sig } = label;
		const result = stmt.run(src, uri, cid, val, neg ? 1 : 0, cts, exp, sig);
		if (!result.changes) throw new Error("Failed to insert label");

		return Number(result.lastInsertRowid);
    }

    searchLabels(cursor?: number, limit = 50, uriPatterns: string[] = [], sources: string[] = []) {
		const patterns = uriPatterns.includes("*") ? [] : uriPatterns.map((pattern) => {
			pattern = pattern.replaceAll(/%/g, "").replaceAll(/_/g, "\\_");

			const starIndex = pattern.indexOf("*");
			if (starIndex === -1) return pattern;

			if (starIndex !== pattern.length - 1) {
				throw new XRPCError(400, {
					kind: "InvalidRequest",
					description: "Only trailing wildcards are supported in uriPatterns",
				});
			}
			return pattern.slice(0, -1) + "%";
		});

		const stmt = this.db.prepare(`
			SELECT * FROM labels
			WHERE 1 = 1
			${patterns.length ? "AND " + patterns.map(() => "uri LIKE ?").join(" OR ") : ""}
			${sources.length ? `AND src IN (${sources.map(() => "?").join(", ")})` : ""}
			${cursor ? "AND id > ?" : ""}
			ORDER BY id ASC
			LIMIT ?
		`);

		const params = [];
		if (patterns.length) params.push(...patterns);
		if (sources.length) params.push(...sources);
		if (cursor) params.push(cursor);
		params.push(limit);

		return stmt.all(params) as Array<SavedLabel>;
    }

    isCursorInTheFuture(cursor: number) {
        const latest = this.db.prepare(`
            SELECT MAX(id) AS id FROM labels
        `).get() as { id: number };

        return cursor > latest.id;
    }

    iterateLabels(cursor = 0) {
        const stmt = this.db.prepare<[number]>(`
            SELECT * FROM labels
            WHERE id > ?
            ORDER BY id ASC
        `);

        return stmt.iterate(cursor) as Iterable<SavedLabel>;
    }
}
