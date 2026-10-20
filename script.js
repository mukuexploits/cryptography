'use strict';
const $=id=>document.getElementById(id),enc=new TextEncoder(),dec=new TextDecoder(),S=crypto.subtle;
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),ub64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
const stat=(id,m,e)=>{const el=$(id);el.textContent=m;el.classList.toggle('err',!!e)};
const copy=async t=>{try{await navigator.clipboard.writeText(t)}catch{}};
const pulse=id=>{const f=$(id);f.classList.remove('go');void f.offsetWidth;f.classList.add('go')};
// nav, clock, hero stream
$('menu').onclick=()=>$('nav').classList.toggle('open');
const t0=Date.now();setInterval(()=>{const s=Math.floor((Date.now()-t0)/1e3);$('clock').textContent=String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0')},1e3);
setInterval(()=>{$('stream').textContent=hex(rnd(300)).replace(/(.{2})/g,'$1 ')},1200);
// workbench
let aesKey=null,rsa=null;const counts=()=>{$('mc').textContent=$('msg').value.length+' chars';$('oc').textContent=$('out').value.length+' chars'};
$('msg').oninput=counts;
const pbeKey=(pw,salt,it,usage)=>S.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']).then(k=>S.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:it},k,{name:'AES-GCM',length:256},false,usage));
const ITER=310000;
$('gen').onclick=async()=>{try{const a=$('alg').value;if(a==='aes'){aesKey=await S.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);stat('bs','New 256-bit AES key generated (memory only).')}else if(a==='rsa'){rsa=await S.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},false,['encrypt','decrypt']);stat('bs','RSA-2048 key pair generated (memory only).')}else stat('bs','Password mode derives its key from your password; nothing to generate.')}catch(e){stat('bs','Key generation failed: '+e.message,1)}};
$('enc').onclick=async()=>{try{const a=$('alg').value,m=$('msg').value;if(!m)throw Error('Enter a message first.');pulse('flow');let pk;
if(a==='aes'){if(!aesKey)throw Error('Generate a key first.');const iv=rnd(12),ct=await S.encrypt({name:'AES-GCM',iv,tagLength:128},aesKey,enc.encode(m));pk={alg:'AES-256-GCM',iv:b64(iv),ct:b64(ct)}}
else if(a==='pbe'){const pw=$('pw').value;if(!pw)throw Error('Enter a password.');const salt=rnd(16),iv=rnd(12),k=await pbeKey(pw,salt,ITER,['encrypt']),ct=await S.encrypt({name:'AES-GCM',iv,tagLength:128},k,enc.encode(m));pk={alg:'PBKDF2-SHA256+AES-256-GCM',iter:ITER,salt:b64(salt),iv:b64(iv),ct:b64(ct)}}
else{if(!rsa)throw Error('Generate an RSA key pair first.');if(enc.encode(m).length>190)throw Error('RSA-OAEP-2048/SHA-256 fits at most 190 bytes. Use hybrid encryption (E2EE section).');pk={alg:'RSA-OAEP-SHA256',ct:b64(await S.encrypt({name:'RSA-OAEP'},rsa.publicKey,enc.encode(m)))}}
$('out').value=JSON.stringify(pk);stat('bs','Encrypted with '+pk.alg+'.');counts()}catch(e){stat('bs',e.message,1)}};
async function decrypt(txt){let p;try{p=JSON.parse(txt)}catch{throw Error('Package is not valid JSON.')}
if(!p||typeof p.ct!=='string'||typeof p.alg!=='string')throw Error('Malformed package.');
try{if(p.alg==='AES-256-GCM'){if(!aesKey)throw Error('No AES key in memory.');return dec.decode(await S.decrypt({name:'AES-GCM',iv:ub64(p.iv),tagLength:128},aesKey,ub64(p.ct)))}
if(p.alg.startsWith('PBKDF2')){if(!$('pw').value)throw Error('Enter the password.');const it=Number(p.iter);if(!(it>=1e5&&it<=2e6))throw Error('Bad iteration count.');const k=await pbeKey($('pw').value,ub64(p.salt),it,['decrypt']);return dec.decode(await S.decrypt({name:'AES-GCM',iv:ub64(p.iv),tagLength:128},k,ub64(p.ct)))}
if(p.alg==='RSA-OAEP-SHA256'){if(!rsa)throw Error('No RSA private key in memory.');return dec.decode(await S.decrypt({name:'RSA-OAEP'},rsa.privateKey,ub64(p.ct)))}}
catch(e){if(e.name==='OperationError')throw Error('Decryption failed: wrong key/password or data was tampered with.');throw e}
throw Error('Unknown algorithm.')}
$('dec').onclick=async()=>{try{pulse('flow');const t=$('msg').value.trim().startsWith('{')?$('msg').value:$('out').value;$('out').value=await decrypt(t);stat('bs','Decrypted successfully.');counts()}catch(e){stat('bs',e.message,1)}};
$('tam').onclick=async()=>{try{const p=JSON.parse($('out').value),b=ub64(p.ct);b[0]^=1;p.ct=b64(b);await decrypt(JSON.stringify(p));stat('bs','Unexpected: tampered data decrypted.',1)}catch(e){stat('bs','Tamper test: '+e.message)}};
$('cpy').onclick=()=>{copy($('out').value);stat('bs','Output copied.')};
$('clr').onclick=()=>{$('msg').value=$('out').value=$('pw').value='';counts();stat('bs','Cleared.')};
// encoding
const be=s=>b64(enc.encode(s)),bd=s=>dec.decode(ub64(s.trim()));
const he=s=>hex(enc.encode(s)),hd=s=>{s=s.replace(/\s/g,'');if(!/^([0-9a-f]{2})*$/i.test(s))throw Error('Invalid hex: use pairs of 0-9a-f.');return dec.decode(Uint8Array.from(s.match(/../g)||[],h=>parseInt(h,16)))};
const E={b64:[be,bd],hex:[he,hd],url:[encodeURIComponent,decodeURIComponent]};
const conv=i=>{try{$('eo').value=E[$('em').value][i]($('ei').value);stat('es','Done.')}catch(e){stat('es','Invalid input for this mode.',1)}};
$('ee').onclick=()=>conv(0);$('ed').onclick=()=>conv(1);$('ex').onclick=()=>{$('ei').value='Hello, MUKU!';conv(0)};
$('ec').onclick=()=>copy($('eo').value);$('el').onclick=()=>{$('ei').value=$('eo').value=''};
// hashing
const H=(a,s)=>S.digest(a,enc.encode(s)).then(hex);
$('hg').onclick=async()=>{$('ho').textContent=await H($('ha').value,$('hi').value)};
$('hc').onclick=()=>copy($('ho').textContent);
$('hv').onclick=async()=>{const a=$('ha').value,s=$('hi').value||'hello',s2=s.slice(0,-1)+String.fromCharCode(s.charCodeAt(s.length-1)^1);const [x,y]=await Promise.all([H(a,s),H(a,s2)]);let d=0;for(let i=0;i<x.length;i++)d+=(parseInt(x[i],16)^parseInt(y[i],16)).toString(2).replace(/0/g,'').length;$('ho').textContent=x+'\n'+y+'\nOne character changed → '+d+' of '+x.length*4+' bits differ'};
const ceq=(a,b)=>{let r=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)r|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return r===0};
$('hcb').onclick=()=>{const m=ceq($('ho').textContent.split('\n')[0].toLowerCase(),$('hcmp').value.trim().toLowerCase());stat('hs',m?'Hashes match.':'Hashes differ.',!m)};
// E2EE simulator
let E2={};const log=m=>$('elog').textContent+=m+'\n';
const rk=()=>S.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
const step=(id,fn)=>$(id).onclick=async()=>{try{pulse('eflow');await fn()}catch(e){log('Error: '+(e.name==='OperationError'?'cryptographic operation failed':e.message))}};
step('s1',async()=>{E2={a:await rk(),b:await rk()};$('bp').textContent='Bob public key (shareable): '+b64(await S.exportKey('spki',E2.b.publicKey)).slice(0,60)+'…\nBob private key: held in memory, never shown.';log('1-2. Demo RSA key pairs created; public keys separate from private keys.')});
step('s2',async()=>{if(!$('am').value)throw Error('Alice needs a message.');E2.m=$('am').value;$('ap').textContent='Plaintext: '+E2.m;log('3. Alice composed a message.')});
step('s3',async()=>{if(!E2.b||!E2.m)throw Error('Generate keys and compose first.');const k=await S.generateKey({name:'AES-GCM',length:256},true,['encrypt']),iv=rnd(12);const ct=await S.encrypt({name:'AES-GCM',iv},k,enc.encode(E2.m));const wk=await S.encrypt({name:'RSA-OAEP'},E2.b.publicKey,await S.exportKey('raw',k));E2.pkt={iv:b64(iv),ct:b64(ct),key:b64(wk)};$('ap').textContent+='\nPacket: '+JSON.stringify(E2.pkt).slice(0,120)+'…';log('4-6. Random session key encrypts message (AES-GCM); session key wrapped with Bob\'s public key.')});
step('s4',async()=>{if(!E2.pkt)throw Error('Encrypt first.');E2.net=E2.pkt;$('bp').textContent+='\nReceived (network sees only): '+JSON.stringify(E2.net).slice(0,100)+'…';log('7. Packet crossed the untrusted network: ciphertext only.')});
step('s5',async()=>{if(!E2.net)throw Error('Send the packet first.');const raw=await S.decrypt({name:'RSA-OAEP'},E2.b.privateKey,ub64(E2.net.key)),k=await S.importKey('raw',raw,'AES-GCM',false,['decrypt']);const pt=dec.decode(await S.decrypt({name:'AES-GCM',iv:ub64(E2.net.iv)},k,ub64(E2.net.ct)));$('bp').textContent+='\nRecovered: '+pt;log('8-10. Bob recovered the session key, then the message.')});
$('s6').onclick=()=>{E2={};$('ap').textContent=$('bp').textContent=$('elog').textContent='';};
// classical
const shift=(s,n)=>s.replace(/[a-z]/gi,c=>{const b=c<'a'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+n%26+26)%26+b)});
function classic(d){const s=$('ci').value,k=$('ck').value,t=$('cc').value;
if(t==='rot13')return shift(s,13);
if(t==='caesar'){if(!/^-?\d+$/.test(k))throw Error('Shift must be an integer.');return shift(s,d*parseInt(k))}
if(t==='vig'){if(!/^[a-z]+$/i.test(k))throw Error('Key must be letters only.');let i=0;return s.replace(/[a-z]/gi,c=>{const n=k[i++%k.length].toLowerCase().charCodeAt(0)-97;return shift(c,d*n)})}
if(!k)throw Error('Enter a key.');const kb=enc.encode(k);
if(d>0)return hex(enc.encode(s).map((b,i)=>b^kb[i%kb.length]));const h=s.replace(/\s/g,'');if(!/^([0-9a-f]{2})*$/i.test(h))throw Error('XOR decrypt expects hex input.');return dec.decode(Uint8Array.from(h.match(/../g)||[],(x,i)=>parseInt(x,16)^kb[i%kb.length]))}
const cl=d=>()=>{try{$('co').textContent=classic(d);stat('cs','Done.')}catch(e){stat('cs',e.message,1)}};
$('ce').onclick=cl(1);$('cd').onclick=cl(-1);
$('cb').onclick=()=>{$('co').textContent=Array.from({length:25},(_,i)=>'Shift '+(i+1)+': '+shift($('ci').value,-(i+1))).join('\n')};
// signatures
let sk=null,sig=null;
$('kg').onclick=async()=>{sk=await S.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);sig=null;stat('ss','P-256 key pair generated (private key hidden).')};
$('sg').onclick=async()=>{if(!sk)return stat('ss','Generate keys first.',1);const s=await S.sign({name:'ECDSA',hash:'SHA-256'},sk.privateKey,enc.encode($('sm').value));$('ssig').value=b64(s);stat('ss','Signed.')};
$('vf').onclick=async()=>{try{if(!sk)throw Error('Generate keys first.');const ok=await S.verify({name:'ECDSA',hash:'SHA-256'},sk.publicKey,ub64($('ssig').value.trim()),enc.encode($('sm').value));stat('ss',ok?'Signature VALID: message unchanged, signed by this key.':'Signature INVALID: message or signature was modified.',!ok)}catch(e){stat('ss',e.message.includes('Generate')?e.message:'Malformed signature.',1)}};
// terminal
const T={help:()=>'Commands: help about algorithms demo aes|hash|base64|e2ee clear',about:()=>'MUKU EXPLOITS Crypto Lab — educational, local-only.',algorithms:()=>'AES-GCM, PBKDF2, RSA-OAEP, SHA-2, ECDSA P-256, Base64/Hex/URL, Caesar/Vigenère/XOR',
'demo aes':async()=>{const k=await S.generateKey({name:'AES-GCM',length:256},false,['encrypt']);return 'Fresh IV: '+hex(rnd(12))+'\nCiphertext: '+hex(await S.encrypt({name:'AES-GCM',iv:rnd(12)},k,enc.encode('demo')))},
'demo hash':async()=>'SHA-256("demo") = '+await H('SHA-256','demo'),'demo base64':()=>'Base64("demo") = '+be('demo'),'demo e2ee':()=>{location.hash='e2ee';return 'Opening E2EE simulator…'}};
$('tin').onkeydown=async e=>{if(e.key!=='Enter')return;const c=e.target.value.trim().toLowerCase();e.target.value='';if(c==='clear'){$('tout').textContent='';return}
const r=T[c]?await T[c]():'Unknown command. Type help.';$('tout').textContent+='\n> '+c+'\n'+r};
$('all').onclick=()=>{aesKey=rsa=sk=null;E2={};document.querySelectorAll('textarea,input').forEach(x=>x.value='');document.querySelectorAll('pre.out,#ho,#ap,#bp,#elog,#co').forEach(x=>x.textContent='');counts()};
