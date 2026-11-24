const test=require('node:test');const assert=require('node:assert/strict');
const {PublicKey,Transaction,TransactionInstruction}=require('@solana/web3.js');
const sdk=require('../dist');
const pk=n=>new PublicKey(new Uint8Array(32).fill(n));
const meta=(pubkey,isSigner=false,isWritable=false)=>({pubkey,isSigner,isWritable});
const ix=(program,keys)=>new TransactionInstruction({programId:pk(program),keys,data:Buffer.from([7,8,9])});
const compile=(instructions,payer=pk(1))=>new Transaction({feePayer:payer,recentBlockhash:pk(9).toBase58()}).add(...instructions).compileMessage();
test('V3 complete-message elevation and cross-language compiled vector',()=>{
 const action=ix(2,[meta(pk(1)),meta(pk(3)),meta(pk(3))]);
 const normal=compile([action]);const writable=compile([action,ix(4,[meta(pk(3),false,true)])]);
 const signer=compile([action,ix(4,[meta(pk(3),true)])]);
 const hash=m=>Buffer.from(sdk.hashCompiledAction(m,0));
 assert.notDeepEqual(hash(normal),hash(writable));assert.notDeepEqual(hash(normal),hash(signer));
 assert.notDeepEqual(hash(normal),hash(compile([action],pk(5))));
 assert.equal(hash(writable).toString('hex'),'6777901e314a11c4c8bad75331b061ab7c90c832603f5970937033ff21fd51cc');
 assert.throws(()=>sdk.validateCompiledAction(writable,0,hash(normal)),/V3/);
 assert.throws(()=>sdk.hashAction(Uint8Array.of(7),[pk(1)],new Uint8Array()),/legacy/);
});
test('runtime program demotion and reserved writes fail closed',()=>{
 const action=ix(2,[meta(pk(2),false,true)]);
 assert.deepEqual(sdk.hashCompiledAction(compile([action]),0),sdk.hashAction(Uint8Array.of(7),[meta(pk(2))],Uint8Array.of(8,9)));
 const clock=new PublicKey('SysvarC1ock11111111111111111111111111111111');
 assert.throws(()=>sdk.hashCompiledAction(compile([ix(2,[meta(clock,false,true)])]),0),/reserved/);
});
test('normal Nitro builder validates complete metadata before returning',()=>{
 const payer=pk(1),workload=pk(6),nonce=new Uint8Array(32).fill(6),document=Uint8Array.of(0x80);
 const consumer=ix(2,[meta(payer)]);
 const verifier=sdk.buildVerifyNitroAttestationIx(payer,workload,1,1,new Uint8Array(32),document,nonce);
 verifier.data=Buffer.alloc(0);
 const expected=sdk.hashCompiledAction(compile([verifier,consumer]),1);
 const build=hash=>sdk.buildVerifyNitroAttestationTx(payer,workload,1,1,hash,document,nonce,pk(9).toBase58(),consumer);
 const tx=build(expected);
 assert.deepEqual(sdk.hashCompiledAction(tx.compileMessage(),1),expected);
 assert.throws(()=>build(new Uint8Array(32)),/V3/);
});
