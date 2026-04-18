(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();function e(e){let t=new Uint8Array(e);return crypto.getRandomValues(t),t}function t(e){let t=0;for(let n of e)t+=n.length;let n=new Uint8Array(t),r=0;for(let t of e)n.set(t,r),r+=t.length;return n}async function n(e){let t=new Uint8Array(e.length);t.set(e);let n=await crypto.subtle.digest(`SHA-256`,t.buffer);return new Uint8Array(n)}async function r(t,n){if(!Number.isInteger(n)||n<2)throw Error(`N must be an integer >= 2`);let r=[];for(let i=0;i<n-1;i+=1)r.push(e(t.length));let i=new Uint8Array(t.length);for(let e=0;e<t.length;e+=1){let n=t[e];for(let t=0;t<r.length;t+=1)n^=r[t][e];i[e]=n}return r.push(i),r}function i(e){if(e.length===0)throw Error(`At least one share is required`);let t=e[0].length;for(let n of e)if(n.length!==t)throw Error(`All shares must have equal length`);let n=new Uint8Array(t);for(let r=0;r<t;r+=1){let t=0;for(let n of e)t^=n[r];n[r]=t}return n}function a(e,t){if(e.length===0)throw Error(`At least one share is required`);if(!Number.isInteger(t)||t<0||t>=e.length)throw Error(`missingIndex out of range`);let n=e[0].length;for(let t of e)if(t.length!==n)throw Error(`All shares must have equal length`);let r=new Uint8Array(n);for(let i=0;i<n;i+=1){let n=0;for(let r=0;r<e.length;r+=1)r!==t&&(n^=e[r][i]);r[i]=n}return r}async function o(r,i){let a=i?new Uint8Array(i):e(16);return{commitment:await n(t([a,r])),salt:a}}async function s(e,r,i){let a=await n(t([r,e]));if(a.length!==i.length)return!1;let o=0;for(let e=0;e<a.length;e+=1)o|=a[e]^i[e];return o===0}async function c(e){if(e.length===0)throw Error(`At least one leaf is required`);let r=e.slice();for(;r.length>1;){let e=[];for(let i=0;i<r.length;i+=2){let a=r[i],o=r[i+1]??r[i];e.push(await n(t([a,o])))}r=e}return r[0]}async function l(e,r){if(e.length===0)throw Error(`At least one leaf is required`);if(!Number.isInteger(r)||r<0||r>=e.length)throw Error(`revealIndex out of range`);let i=[],a=r,o=e.slice();for(;o.length>1;){let e=a%2==1?a-1:a+1;i.push(o[e]??o[a]);let r=[];for(let e=0;e<o.length;e+=2){let i=o[e],a=o[e+1]??o[e];r.push(await n(t([i,a])))}a=Math.floor(a/2),o=r}return{root:o[0],proof:i}}async function u(e,r,i,a){if(!Number.isInteger(r)||r<0)return!1;let o=e,s=r;for(let e of i)o=s%2==0?await n(t([o,e])):await n(t([e,o])),s=Math.floor(s/2);if(o.length!==a.length)return!1;let c=0;for(let e=0;e<o.length;e+=1)c|=o[e]^a[e];return c===0}function d(e){return Array.from(e,e=>e.toString(16).padStart(2,`0`)).join(``)}function f(e){let t=e.trim().replace(/^0x/i,``);if(t.length===0)return new Uint8Array;if(t.length%2!=0)throw Error(`Hex input must contain an even number of digits`);if(!/^[0-9a-fA-F]+$/.test(t))throw Error(`Hex input contains non-hex characters`);let n=new Uint8Array(t.length/2);for(let e=0;e<t.length;e+=2)n[e/2]=Number.parseInt(t.slice(e,e+2),16);return n}function p(e){if(!Number.isInteger(e)||e<=0||e>256)throw Error(`maxExclusive must be an integer in [1, 256]`);let t=new Uint8Array(1);for(;;){crypto.getRandomValues(t);let n=t[0];if(n<256-256%e)return n%e}}function m(e,t){let n=e%t;return n<0?n+t:n}function h(e){if(!Number.isInteger(e.N)||e.N<2)throw Error(`params.N must be >= 2`);if(!Number.isInteger(e.tau)||e.tau<1)throw Error(`params.tau must be >= 1`);if(!Number.isInteger(e.q)||e.q<2||e.q>251)throw Error(`params.q must be in [2, 251] for byte-safe demo arithmetic`)}function g(e){let{A:t,b:n,q:r}=e;if(!Number.isInteger(r)||r<2)throw Error(`Invalid field modulus`);if(!Array.isArray(t)||t.length===0)throw Error(`A must be a non-empty matrix`);let i=t[0]?.length??0;if(i===0)throw Error(`A must have at least one column`);for(let e of t){if(e.length!==i)throw Error(`A must be rectangular`);for(let t of e)if(!Number.isInteger(t)||t<0||t>=r)throw Error(`A contains out-of-range field element`)}if(n.length!==t.length)throw Error(`b length must equal matrix row count`);for(let e of n)if(!Number.isInteger(e)||e<0||e>=r)throw Error(`b contains out-of-range field element`)}function _(e,t,n){return e.map(e=>{let r=0;for(let i=0;i<e.length;i+=1)r=m(r+e[i]*t[i],n);return r})}function ee(e,t,n){if(e.length!==t.length)throw Error(`Vector length mismatch`);let r=Array(e.length);for(let i=0;i<e.length;i+=1)r[i]=m(e[i]+t[i],n);return r}function te(e,t,n){if(e.length!==t.length)throw Error(`Vector length mismatch`);let r=Array(e.length);for(let i=0;i<e.length;i+=1)r[i]=m(e[i]-t[i],n);return r}function v(e){return Uint8Array.from(e.map(e=>e&255))}function y(e){let t=0;for(let n of e)t+=n.length;let n=new Uint8Array(t),r=0;for(let t of e)n.set(t,r),r+=t.length;return n}function b(e,t){return y([v(e),v(t)])}async function x(e){let t=new Uint8Array(e.length);t.set(e);let n=await crypto.subtle.digest(`SHA-256`,t.buffer);return new Uint8Array(n)}function S(e,t,n){let r=e[t%e.length];return n&n-1?r%n:r&n-1}function C(e,t){if(e.length!==t.length)return!1;for(let n=0;n<e.length;n+=1)if(e[n]!==t[n])return!1;return!0}function ne(e,t){if(e.length!==t.length)return!1;let n=0;for(let r=0;r<e.length;r+=1)n|=e[r]^t[r];return n===0}function re(e,t,n){let r=e.length,i=[],a=Array(r).fill(0);for(let e=0;e<t-1;e+=1){let e=Array(r);for(let t=0;t<r;t+=1)e[t]=p(n),a[t]=m(a[t]+e[t],n);i.push(e)}let o=Array(r);for(let t=0;t<r;t+=1)o[t]=m(e[t]-a[t],n);return i.push(o),i}function ie(e,t,n){if(e.length!==t)throw Error(`Witness length mismatch with matrix columns`);for(let t of e)if(!Number.isInteger(t)||t<0||t>=n)throw Error(`Witness contains out-of-range field element`)}async function w(e,t,n){if(!Number.isInteger(e)||e<=0||!Number.isInteger(t)||t<=0)throw Error(`n and m must be positive integers`);if(!Number.isInteger(n)||n<2||n>251)throw Error(`q must be in [2, 251] for this demo`);let r=Array.from({length:e},()=>p(n)),i=Array.from({length:t},()=>Array.from({length:e},()=>p(n)));return{statement:{A:i,b:_(i,r,n),q:n},witness:r}}async function ae(e,t,n){h(n),g(e);let r=e.q,i=e.A[0].length;ie(t,i,r);let a=re(t,n.N,r),s=a.map(t=>_(e.A,t,r)),l=Array(e.b.length).fill(0);for(let e of s)l=ee(l,e,r);if(!C(l,e.b))throw Error(`MPC share outputs do not sum to public target b`);let u=[],d=[];for(let e=0;e<n.N;e+=1){let t=a[e],n=s[e],{commitment:r,salt:i}=await o(b(t,n));d.push(r),u.push({share:t,output:n,salt:i})}return{merkleRoot:await c(d),commitments:d,views:u,partyOutputs:s}}function T(e,t){return y([e,...t])}async function E(e,t,n,r){h(r),g(t);let i=[];for(let e=0;e<r.tau;e+=1)i.push(await ae(t,n,r));let a=i.map(e=>e.merkleRoot),o=await x(T(e,a)),s=[],c=[];for(let e=0;e<r.tau;e+=1){let t=S(o,e,r.N);s.push(t);let n=[];for(let a=0;a<r.N;a+=1){if(a===t){n.push(null);continue}let r=i[e].views[a],o=await l(i[e].commitments,a);n.push({share:r.share,output:r.output,salt:r.salt,merkleProof:o.proof})}c.push(n)}let u=[];return u.push(`message = ${d(e)}`),a.forEach((e,t)=>{u.push(`root_${t+1} = ${d(e)}`)}),u.push(`challenge = SHA-256(message || roots) = ${d(o)}`),s.forEach((e,t)=>{u.push(`round ${t+1}: hidden party = ${e}`)}),{signature:{merkleRoots:a,challenge:o,hiddenParties:s,revealedViews:c},challengeDerivation:u.join(`
`)}}async function oe(e,t,n,r){try{if(h(r),g(t),n.merkleRoots.length!==r.tau)return{valid:!1,failureReason:`Wrong number of Merkle roots`};if(n.revealedViews.length!==r.tau)return{valid:!1,failureReason:`Wrong number of rounds in revealed views`};if(n.hiddenParties.length!==r.tau)return{valid:!1,failureReason:`Wrong number of hidden party indexes`};if(!ne(await x(T(e,n.merkleRoots)),n.challenge))return{valid:!1,failureReason:`Fiat-Shamir challenge mismatch`};for(let e=0;e<r.tau;e+=1){let i=S(n.challenge,e,r.N);if(n.hiddenParties[e]!==i)return{valid:!1,failureReason:`Hidden party mismatch in round ${e+1}`};let a=n.revealedViews[e];if(a.length!==r.N)return{valid:!1,failureReason:`Wrong party count in round ${e+1}`};let c=Array(t.b.length).fill(0);for(let l=0;l<r.N;l+=1){let r=a[l];if(l===i){if(r!==null)return{valid:!1,failureReason:`Hidden party ${l} was revealed in round ${e+1}`};continue}if(r===null)return{valid:!1,failureReason:`Missing revealed party ${l} in round ${e+1}`};if(r.share.length!==t.A[0].length)return{valid:!1,failureReason:`Share length mismatch in round ${e+1}, party ${l}`};if(r.output.length!==t.b.length)return{valid:!1,failureReason:`Output length mismatch in round ${e+1}, party ${l}`};for(let n of r.share)if(!Number.isInteger(n)||n<0||n>=t.q)return{valid:!1,failureReason:`Share value out of range in round ${e+1}, party ${l}`};for(let n of r.output)if(!Number.isInteger(n)||n<0||n>=t.q)return{valid:!1,failureReason:`Output value out of range in round ${e+1}, party ${l}`};if(!C(_(t.A,r.share,t.q),r.output))return{valid:!1,failureReason:`Local MPC output mismatch in round ${e+1}, party ${l}`};let d=b(r.share,r.output),{commitment:f}=await o(d,r.salt);if(!await s(d,r.salt,f))return{valid:!1,failureReason:`Commitment self-check failed in round ${e+1}, party ${l}`};if(!await u(f,l,r.merkleProof,n.merkleRoots[e]))return{valid:!1,failureReason:`Merkle proof failed in round ${e+1}, party ${l}`};for(let e=0;e<c.length;e+=1)c[e]=m(c[e]+r.output[e],t.q)}let l=te(t.b,c,t.q);for(let n of l)if(n<0||n>=t.q)return{valid:!1,failureReason:`Implied hidden output out of range in round ${e+1}`}}return{valid:!0}}catch(e){return{valid:!1,failureReason:e instanceof Error?e.message:`Unknown verification error`}}}function D(e){let t=new Uint8Array(1),n=256-256%e;for(;;)if(crypto.getRandomValues(t),t[0]<n)return t[0]%e}function se(e,t){let n=e%t;return n<0?n+t:n}function O(e,t,n){return e.map(e=>{let r=0;for(let i=0;i<e.length;i+=1)r=se(r+e[i]*t[i],n);return r})}function ce(e){let t=Array.from({length:e},(e,t)=>t);for(let n=e-1;n>0;--n){let e=D(n+1),r=t[n];t[n]=t[e],t[e]=r}return t}function k(e,t){if(e.length!==t.length)throw Error(`Permutation length mismatch`);let n=Array(e.length);for(let r=0;r<t.length;r+=1)n[r]=e[t[r]];return n}function le(e){let t=Array(e.length);for(let n=0;n<e.length;n+=1)t[e[n]]=n;return t}function A(e){return{N:e.N,tau:e.tau,q:e.q}}function j(e,t){return{A:e.H,b:e.b,q:t}}function ue(e){let t={merkleRoots:e.merkleRoots.map(e=>d(e)),challenge:d(e.challenge),hiddenParties:e.hiddenParties,revealedViews:e.revealedViews.map(e=>e.map(e=>e?{share:e.share,output:e.output,salt:d(e.salt),merkleProof:e.merkleProof.map(e=>d(e))}:null))};return new TextEncoder().encode(JSON.stringify(t))}function de(e){let t=JSON.parse(new TextDecoder().decode(e));return{merkleRoots:t.merkleRoots.map(e=>f(e)),challenge:f(t.challenge),hiddenParties:t.hiddenParties,revealedViews:t.revealedViews.map(e=>e.map(e=>e?{share:e.share,output:e.output,salt:f(e.salt),merkleProof:e.merkleProof.map(e=>f(e))}:null))}}async function fe(e){let t=Array.from({length:e.n},()=>D(e.q)),n=ce(e.n),r=k(t,le(n)),i=Array.from({length:e.m},()=>Array.from({length:e.n},()=>D(e.q)));return{publicKey:{H:i,y:r,b:O(i,t,e.q)},privateKey:{pi:n,x:t}}}async function pe(e,t,n){let r=k(t.publicKey.y,t.privateKey.pi),{signature:i}=await E(e,j(t.publicKey,n.q),r,A(n));return ue(i)}async function M(e,t,n,r){let i=de(n);return(await oe(e,j(t,r.q),i,A(r))).valid}function me(e){let t=e.tau*32,n=e.n+e.m+16,r=e.tau*(e.N-1)*n,i=Math.ceil(Math.log2(e.N)),a=e.tau*(e.N-1)*i*32;return{bytes:t+32+r+a,breakdown:{merkleRoots:t,challenge:32,revealedViews:r,merkleProofs:a}}}function he(e,t,n){let r=O(e.H,k(e.y,t),n);if(r.length!==e.b.length)return!1;for(let t=0;t<r.length;t+=1)if(r[t]!==e.b[t])return!1;return!0}var N=document.querySelector(`#app`);if(!N)throw Error(`Missing #app root`);var ge=N,P=new TextEncoder,F={secretHex:`2a`,N:4,q:251,shares:[],statement:null,witness:null,round:null,hiddenParty:null,verificationText:``},I={N:8,tau:4,q:251},L=null,R=null,z=`Authenticated by Paul Clark, LCPL`,B=``,V=[],H={n:8,m:4,q:251,N:8,tau:4},U=null,W=`Toy PERK signature demo`,G=null,K=`No signature generated yet.`,q=!1,J=[],Y=0;function _e(){return document.documentElement.getAttribute(`data-theme`)===`light`?`light`:`dark`}function ve(e,t){t===`dark`?(e.textContent=`🌙`,e.setAttribute(`aria-label`,`Switch to light mode`)):(e.textContent=`☀️`,e.setAttribute(`aria-label`,`Switch to dark mode`))}function ye(e){ve(e,_e()),e.addEventListener(`click`,()=>{let t=_e()===`dark`?`light`:`dark`;document.documentElement.setAttribute(`data-theme`,t),localStorage.setItem(`theme`,t),ve(e,t)})}function X(e){let t=new Uint8Array(1),n=256-256%e;for(;;)if(crypto.getRandomValues(t),t[0]<n)return t[0]%e}function be(e){let t=X(256),n=X(256);J=[t,n,t^n^e],Y=X(3)}function xe(e,t){let n=e%t;return n<0?n+t:n}async function Se(){let e=f(F.secretHex);if(e.length===0)throw Error(`Secret cannot be empty`);F.shares=await r(e,F.N),F.round=null,F.hiddenParty=null,F.verificationText=`Shares generated. Run MPC next.`}async function Ce(){let e=await w(4,3,F.q);F.statement=e.statement,F.witness=e.witness,F.round=await ae(e.statement,e.witness,{N:F.N,tau:1,q:F.q}),F.hiddenParty=null,F.verificationText=`MPC views committed. Trigger challenge.`}function we(){if(!F.round){F.verificationText=`Run MPC before challenge.`;return}F.hiddenParty=X(F.N);let e=document.querySelector(`#challenge-live`);e&&(e.textContent=`Challenge selected: hide party ${F.hiddenParty+1}.`),F.verificationText=`Challenge set: party ${F.hiddenParty+1} is hidden.`}async function Te(){if(!F.round||!F.statement||F.hiddenParty===null){F.verificationText=`Split, run MPC, and challenge first.`;return}let e=F.round.partyOutputs.filter((e,t)=>t!==F.hiddenParty),t=Array(F.statement.b.length).fill(0);for(let n of e)for(let e=0;e<n.length;e+=1)t[e]=xe(t[e]+n[e],F.q);let n=F.statement.b.map((e,n)=>xe(e-t[n],F.q)),r=(F.hiddenParty+1)%F.N,i=F.round.views[r];F.verificationText=d((await o(Uint8Array.from([...i.share,...i.output]),i.salt)).commitment)===d(F.round.commitments[r])?`Verifier accepted revealed views. Implied hidden output: [${n.join(`, `)}].`:`Verifier rejected: commitment mismatch.`}async function Z(){let e=await w(4,3,I.q);L=e.statement,R=e.witness;let t=await E(P.encode(z),L,R,I);B=t.challengeDerivation,V=t.signature.hiddenParties}async function Q(){U=await fe(H),G=null,K=`Keypair generated. Ready to sign.`}async function Ee(){U||await Q(),U&&(G=await pe(P.encode(W),U,H),K=await M(P.encode(W),U.publicKey,G,H)?`VALID signature.`:`INVALID signature.`)}async function De(){if(!U||!G){K=`Generate keypair and signature first.`,$();return}K=await M(P.encode(W),U.publicKey,G,H)?`VALID signature.`:`INVALID signature.`}function Oe(){let e=[];for(let t=0;t<F.N;t+=1){let n=F.hiddenParty===t,r=F.round?.views[t],i=F.shares[t]?d(F.shares[t]):`pending`,a=r?`[${r.output.join(`, `)}]`:`pending`,o=r?`${d(r.salt).slice(0,8)}...`:`pending`,s=F.round?`${d(F.round.commitments[t]).slice(0,12)}...`:`pending`,c=n?`HIDDEN`:`ACTIVE`;e.push(`
      <article
        class="party-card ${n?`hidden`:`active`}"
        tabindex="0"
        aria-label="Party ${t+1}, status ${c.toLowerCase()}"
      >
        <h4>Party ${t+1}</h4>
        <p><strong>Share:</strong> ${i}</p>
        <p><strong>My output:</strong> ${a}</p>
        <p><strong>Salt:</strong> ${o}</p>
        <p><strong>Commitment:</strong> <span role="code" aria-label="Commitment hash for party ${t+1}">${s}</span></p>
        <p class="status">Status: ● ${c}</p>
      </article>
    `)}return e.join(``)}function $(){let e=me(H),t=U?he(U.publicKey,U.privateKey.pi,H.q):!1,n=J[0]??17,r=J[1]??63,o=J[2]??4;ge.innerHTML=`
    <header class="topbar">
      <h1>Signing In Your Head</h1>
      <button id="theme-toggle" class="theme-toggle" type="button" style="position: absolute; top: 0; right: 0"></button>
    </header>

    <main class="layout">
      <section class="panel">
        <h2>Exhibit 1 — The Idea</h2>
        <p>
          You want to prove you know a secret. Normally: show the secret. That reveals it.
          MPC-in-the-Head simulates many parties inside one prover, commits to each view,
          then reveals all but one view for checking.
        </p>
        <div class="card-game">
          <div>
            <h3>Three-card analogy</h3>
            <p>SECRET: ${n^r^o}</p>
            <p>Party A: ${n}</p>
            <p>Party B: ${r}</p>
            <p>Party C: ${o}</p>
            <p>Challenge: hide Party ${[`A`,`B`,`C`][Y]??`A`}</p>
            <p>
              Cheating soundness: one round $1/N$, with repetitions $\tau$ gives $\left(1/N\right)^\tau$.
            </p>
          </div>
          <button id="reshuffle-cards" type="button" aria-label="Reshuffle three-card secret shares">Reshuffle Shares</button>
        </div>
      </section>

      <section class="panel">
        <h2>Exhibit 2 — MPC Party Simulation</h2>
        <div class="controls">
          <label>Secret (hex)
            <input id="secret-hex" value="${F.secretHex}" />
          </label>
          <label>N parties: <span id="n-value">${F.N}</span>
            <input id="n-slider" type="range" min="2" max="8" value="${F.N}" />
          </label>
          <label>Prime field q
            <select id="q-select">
              <option value="101" ${F.q===101?`selected`:``}>101</option>
              <option value="251" ${F.q===251?`selected`:``}>251</option>
            </select>
          </label>
        </div>
        <div class="button-row">
          <button id="split-secret" type="button" aria-label="Split secret into party shares">Split Secret</button>
          <button id="run-mpc" type="button" aria-label="Run MPC round">Run MPC</button>
          <button id="run-challenge" type="button" aria-label="Select hidden party challenge">Challenge</button>
          <button id="run-verify" type="button" aria-label="Verify revealed party views">Verify</button>
        </div>
        <p id="challenge-live" aria-live="polite" class="challenge-live"></p>
        <div class="challenge-arrow">⇢ Challenge picks one hidden party</div>
        <div class="party-grid">
          ${Oe()}
        </div>
        <p>${F.verificationText}</p>
      </section>

      <section class="panel">
        <h2>Exhibit 3 — Fiat-Shamir Signature</h2>
        <label>Message
          <input id="fs-message" value="${z}" />
        </label>
        <div class="button-row">
          <button id="run-fs" type="button" aria-label="Run Fiat Shamir signature derivation">Run Fiat-Shamir</button>
          <button id="tamper-fs" type="button" aria-label="Modify message and recompute challenge">Modify Message</button>
        </div>
        <div class="columns">
          <div>
            <h3>Interactive</h3>
            <pre>Prover -> Commit(views)
Verifier -> Challenge e
Prover -> Reveal all except e</pre>
          </div>
          <div>
            <h3>Fiat-Shamir</h3>
            <pre>e = SHA-256(message || commitments)
Signature = (roots, e, responses)
Verifier recomputes e and checks consistency</pre>
          </div>
        </div>
        <p>Hidden parties per round: ${V.length>0?V.join(`, `):`not generated`}</p>
        <pre class="trace">${B||`Run the demo to show challenge derivation.`}</pre>
      </section>

      <section class="panel">
        <h2>Exhibit 4 — Toy PERK</h2>
        <p>
          Toy PERK relation: find permutation $\pi$ such that $H \cdot \pi(y) = b \mod q$.
          This demo uses tiny parameters for visibility.
        </p>
        <div class="button-row">
          <button id="perk-keygen" type="button" aria-label="Generate toy PERK keypair">Generate PERK Keypair</button>
          <button id="perk-sign" type="button" aria-label="Sign message with toy PERK">Sign</button>
          <button id="perk-verify" type="button" aria-label="Verify toy PERK signature">Verify</button>
          <button id="perk-reveal" type="button" aria-label="Toggle visibility of private permutation">${q?`Hide π`:`Reveal π`}</button>
        </div>
        <label>Message
          <input id="perk-message" value="${W}" />
        </label>
        <p>Signature status: <strong class="${K.includes(`VALID`)?`ok`:`bad`}">${K}</strong></p>
        <p>Key equation check $H \cdot \pi(y)=b$: ${t?`✓`:`pending`}</p>
        <p>Estimated signature size: ~${e.bytes} bytes</p>
        <pre>${JSON.stringify(e.breakdown,null,2)}</pre>
        <pre>${U?`public H rows: ${U.publicKey.H.length}\npublic y: [${U.publicKey.y.join(`, `)}]\npublic b: [${U.publicKey.b.join(`, `)}]\n${q?`private pi: [${U.privateKey.pi.join(`, `)}]`:`private pi: [hidden]`}`:`Generate a keypair to view parameters.`}</pre>
      </section>

      <section class="panel">
        <h2>Exhibit 5 — Security Diversity</h2>
        <p>
          NIST Round 2 additional signatures include Mirath, PERK, RYDE, SDitH, MQOM, and FAEST.
          None are standardized as of 2026. They are under active cryptanalysis.
        </p>
        <table>
          <thead>
            <tr><th>Scheme</th><th>Sig size</th><th>Security basis</th></tr>
          </thead>
          <tbody>
            <tr><td>ML-DSA-2</td><td>2,420 B</td><td>Lattice</td></tr>
            <tr><td>SLH-DSA-128s</td><td>7,856 B</td><td>Hash</td></tr>
            <tr><td>PERK-I (est.)</td><td>~6,000 B</td><td>Hash + PKP</td></tr>
            <tr><td>Mirath-I (est.)</td><td>~5,700 B</td><td>Hash + MinRank</td></tr>
            <tr><td>FAEST-I (est.)</td><td>~5,700 B</td><td>Hash + AES</td></tr>
          </tbody>
        </table>
        <p>
          Tradeoff: MPCitH signatures are generally larger than ML-DSA, but avoid lattice structure and
          rely on hash commitments plus hard combinatorial statements.
        </p>
        <p>
          Cross-links: crypto-lab-sphincs-ledger, crypto-lab-dilithium-seal,
          crypto-lab-zk-proof-lab, crypto-lab-silent-tally.
        </p>
      </section>
    </main>

  `;let s=document.querySelector(`#theme-toggle`);s&&ye(s),document.querySelector(`#reshuffle-cards`)?.addEventListener(`click`,()=>{be(42),$()});let c=document.querySelector(`#secret-hex`);c?.addEventListener(`input`,()=>{F.secretHex=c.value.trim()});let l=document.querySelector(`#n-slider`);l?.addEventListener(`input`,()=>{F.N=Number.parseInt(l.value,10),$()});let u=document.querySelector(`#q-select`);u?.addEventListener(`change`,()=>{F.q=Number.parseInt(u.value,10)}),document.querySelector(`#split-secret`)?.addEventListener(`click`,async()=>{try{await Se();let e=a(F.shares,0),t=i(F.shares);F.verificationText=`Split complete. Partial XOR(no party 1): ${d(e)}. Full reconstruct: ${d(t)}.`}catch(e){F.verificationText=e instanceof Error?e.message:`Split error`}$()}),document.querySelector(`#run-mpc`)?.addEventListener(`click`,async()=>{await Ce(),$()}),document.querySelector(`#run-challenge`)?.addEventListener(`click`,()=>{we(),$()}),document.querySelector(`#run-verify`)?.addEventListener(`click`,async()=>{await Te(),$()});let f=document.querySelector(`#fs-message`);f?.addEventListener(`input`,()=>{z=f.value}),document.querySelector(`#run-fs`)?.addEventListener(`click`,async()=>{await Z(),$()}),document.querySelector(`#tamper-fs`)?.addEventListener(`click`,async()=>{z=`${z} *`,await Z(),$()});let p=document.querySelector(`#perk-message`);p?.addEventListener(`input`,()=>{W=p.value}),document.querySelector(`#perk-keygen`)?.addEventListener(`click`,async()=>{await Q(),$()}),document.querySelector(`#perk-sign`)?.addEventListener(`click`,async()=>{await Ee(),$()}),document.querySelector(`#perk-verify`)?.addEventListener(`click`,async()=>{await De(),$()}),document.querySelector(`#perk-reveal`)?.addEventListener(`click`,()=>{q=!q,$()})}be(42),Z(),Q(),$();