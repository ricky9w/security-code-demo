import type { APIRoute, APIContext } from "astro";
import { hexToBytes, bytesToHex, xorBytes, generateNonceHex, blake2bHex } from "@/utils/crypto";


interface generateRequestBody {
  sku: string;
  channel: string;
}

export const POST: APIRoute = async (context: APIContext) => {
  try {
    const STATIC_SALT_HEX = context.locals.runtime.env.STATIC_SALT;
    const HMAC_KEY_HEX = context.locals.runtime.env.HMAC_KEY;

    if (!STATIC_SALT_HEX || !HMAC_KEY_HEX) {
      console.error('STATIC_SALT or HMAC_KEY not provided.');
      return new Response(JSON.stringify({ error: 'Internal Error'}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const HMAC_KEY_BYTES = hexToBytes(HMAC_KEY_HEX);

    const requestBody = await context.request.json() as generateRequestBody;
    const sku = requestBody.sku;
    const channel = requestBody.channel;

    if (!sku || !channel) {
      console.warn('SKU or Channel info not provided.');
      return new Response(JSON.stringify({ error: 'Invalid Request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const productInfo = sku + channel;
    const productInfoBytes = hexToBytes(productInfo);

    const nonce = generateNonceHex(4); // 4 bytes, 8 characters
    const nonceBytes = hexToBytes(nonce);

    const dynamicKeyBytes = new Uint8Array(
      await crypto.subtle.digest('SHA-256', hexToBytes(nonce + STATIC_SALT_HEX))
    ).slice(0, 4); // same length as ProductInfo

    const encryptedInfoBytes = xorBytes(productInfoBytes, dynamicKeyBytes);

    const dataForMac = new Uint8Array([...encryptedInfoBytes, ...nonceBytes]);
    const macHex = blake2bHex(dataForMac, HMAC_KEY_BYTES, 8);

    const encryptedInfoHex = bytesToHex(encryptedInfoBytes);
    const securityCode = `${encryptedInfoHex}-${nonce}-${macHex}`;

    return new Response(JSON.stringify({ securityCode: securityCode }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    console.error('Error generating security code: ', error);
    return new Response(JSON.stringify({ error: 'Internal Error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}