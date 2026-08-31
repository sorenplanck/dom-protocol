// Verificação independente do truque ecrecover: address(t·G) via ecrecover.
const { ecrecover, publicToAddress, privateToPublic, bufferToHex } = require('ethereumjs-util');
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const b32 = (x) => Buffer.from(x.toString(16).padStart(64,'0'),'hex');
let fails = 0;
for (const t of [1n, 2n, 12345n, N-1n, 0x9a8b7c6d5e4f00112233445566778899aabbccddeeff00112233445566778899n]) {
  const s = (t * GX) % N;
  const recovered = publicToAddress(ecrecover(Buffer.alloc(32), 27, b32(GX), b32(s)));
  const expected  = publicToAddress(privateToPublic(b32(t)));  // address(t·G)
  const ok = recovered.equals(expected);
  if (!ok) fails++;
  console.log(`t=0x${t.toString(16).slice(0,12)}… ecrecover=${bufferToHex(recovered)} address(t*G)=${bufferToHex(expected)} ${ok?'OK':'MISMATCH'}`);
}
console.log(fails === 0 ? 'TRUQUE ECRECOVER VERIFICADO (5/5)' : `FALHAS: ${fails}`);
