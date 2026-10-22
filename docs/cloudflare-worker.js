/**
 * Cloudflare Worker для tg-ws-proxy (свой бесплатный канал обхода).
 *
 * Зачем: общий пул kws-доменов живёт на чужих Cloudflare-доменах и часто
 * отдаёт HTTP 429 (rate limit) — из-за этого Telegram подключается, но
 * висит на «Обновление...». Свой Worker работает на вашем аккаунте, лимиты
 * не общие, домен не «умирает» вместе с чужими.
 *
 * Как развернуть (5 минут, бесплатно):
 *   1. Зарегистрируйтесь на https://dash.cloudflare.com и подтвердите почту.
 *   2. Compute (Workers & Pages) -> Create application -> Start with Hello World!
 *      -> Deploy.
 *   3. Edit code -> вставьте этот файл целиком -> Deploy.
 *   4. Скопируйте адрес вида my-worker.username.workers.dev и вставьте его
 *      в настройках приложения: «Свой Cloudflare Worker».
 *
 * Код основан на воркере проекта Flowseal/tg-ws-proxy (MIT License,
 * Copyright (c) 2026 Flowseal), адаптирован без изменений протокола.
 */

import { connect } from "cloudflare:sockets";

function toBytes(data) {
	if (data instanceof ArrayBuffer) {
		return new Uint8Array(data);
	}
	if (typeof data === "string") {
		return new TextEncoder().encode(data);
	}
	if (data && typeof data.arrayBuffer === "function") {
		return data.arrayBuffer().then((ab) => new Uint8Array(ab));
	}
	return new Uint8Array();
}

export default {
	async fetch(request) {
		if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
			return new Response("Expected websocket", { status: 426 });
		}

		const url = new URL(request.url);
		if (url.pathname !== "/apiws") {
			return new Response("Not found", { status: 404 });
		}

		const dst = url.searchParams.get("dst");
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		server.accept();

		const socket = connect({ hostname: dst, port: 443 });
		const tcpReader = socket.readable.getReader();
		const tcpWriter = socket.writable.getWriter();

		server.addEventListener("message", async (event) => {
			try {
				await tcpWriter.write(await toBytes(event.data));
			} catch {
				try {
					server.close(1011, "tcp write failed");
				} catch {}
			}
		});

		server.addEventListener("close", async () => {
			try {
				await tcpWriter.close();
			} catch {}
			try {
				socket.close();
			} catch {}
		});

		(async () => {
			try {
				while (true) {
					const { value, done } = await tcpReader.read();
					if (done) {
						break;
					}
					if (value) {
						server.send(value);
					}
				}
			} catch {
			} finally {
				try {
					server.close();
				} catch {}
				try {
					tcpReader.releaseLock();
				} catch {}
				try {
					socket.close();
				} catch {}
			}
		})();

		return new Response(null, { status: 101, webSocket: client });
	},
};
