# Imported SuperScalar files

These files are copied byte-for-byte from SuperScalar (MIT licence, see LICENSE in this directory).
Do not edit them. Re-import with tools/update-import.sh. Workarounds go in core/shim/.

Upstream: https://github.com/8144225309/SuperScalar
Pinned commit: e65739500bbbbb53bc142ad68add40509238264c
Commit date: 2026-11-11T15:11:27-05:00
Commit subject: Merge pull request #478 from 8144225309/fix/client-signing-checks
Imported on: 2026-11-11
secp256k1-zkp pin (from upstream CMakeLists.txt, mirrored in ../../CMakeLists.txt): 6152622613fdf1c5af6f31f74c427c4e9ee120ce

| Local path (relative to core/superscalar) | Upstream path | SHA-256 |
|---|---|---|
| include/superscalar/adaptor.h | include/superscalar/adaptor.h | e59bc4f471365190835849ab0633ae269267f398f3c22cec7a825f587796c34d |
| include/superscalar/bech32m.h | include/superscalar/bech32m.h | f589c120e1ed23e4c0aa21c4906914d83f9e1cfc604cdb0b91b4c7d3bfae8a06 |
| include/superscalar/bip39.h | include/superscalar/bip39.h | 9abe1facdd28860139e9827402844cbbaff794d904a7e6f64f7a6e7156d6e5c4 |
| include/superscalar/bolt11.h | include/superscalar/bolt11.h | 440c94432bbf748e83875a8720e6a5dbe89567a79b1d19d9bb766b3256563915 |
| include/superscalar/channel.h | include/superscalar/channel.h | 180e7e03b2b238e1a654d84a1ab3c910cab7b10b31126ffedde3eaca6f4ada32 |
| include/superscalar/crypto_aead.h | include/superscalar/crypto_aead.h | 4b32bcae21251eedda081353de00622c7fd2b4a124537ca1c4d2daa9fc352e12 |
| include/superscalar/dw_state.h | include/superscalar/dw_state.h | 96d29afd6769aeacb820ef7c525b99ddbbaf76fc7b285c9199e1c1fa944c553b |
| include/superscalar/factory.h | include/superscalar/factory.h | 1993fd231a0da1e150f58ff3d5c70c92581a6e7a16cbff6ebc8c736b050fd140 |
| include/superscalar/fee.h | include/superscalar/fee.h | c74097eaa2a1f61a2e678fd5867204525b63f5aceb5a672eca4132d4314094f3 |
| include/superscalar/fee_estimator.h | include/superscalar/fee_estimator.h | 67eeefa1ee962c81ccd327a32a319cf406d1fbf7616b23e1172effeb28a329c6 |
| include/superscalar/hd_key.h | include/superscalar/hd_key.h | 6adde85fc2f4cff08956caf6ce3e81630b96011f6e9538aba68fcb994ff3d1d7 |
| include/superscalar/htlc_fee_bump.h | include/superscalar/htlc_fee_bump.h | 0488b79e75b6aed22beb76f48780b319f9bbdf4e1889d4252c8dce585a5299ce |
| include/superscalar/ladder.h | include/superscalar/ladder.h | 3b8f5f8f61d94ac954170295d43e51128ff3f2afb606f6f9a5c72b7414bd6efc |
| include/superscalar/musig.h | include/superscalar/musig.h | 0e076462b8055de8bceca5a3d8a87529af54d9d2350c9afa10d124ddbabbb08a |
| include/superscalar/sha256.h | include/superscalar/sha256.h | 919b0863ff2aa09b178bb13817035e170b4f227f07a98b253ccae207c02e75fd |
| include/superscalar/shachain.h | include/superscalar/shachain.h | 027bfd938dec93d9083df9400825e6751c0d51c721273c5ddb3828b5182c9d0d |
| include/superscalar/tapscript.h | include/superscalar/tapscript.h | 7403755ad5e3628258d9c3af3a8e5195566a0873c71501c61e1c2c7d786d26fb |
| include/superscalar/tx_builder.h | include/superscalar/tx_builder.h | aa15d19c4d35c17be91b3e015af7ff7545a142f59876bec06445be6061f0b316 |
| include/superscalar/types.h | include/superscalar/types.h | 1c4aed7b34dd17bad76b42f62c11e6ee4045ddc710741795057ab9bbe476b631 |
| src/adaptor.c | src/adaptor.c | cd68bc7096429fae6ee905fa385fa13de7da10d3a5278c1d7d4c83be5a74b75a |
| src/bech32m.c | src/bech32m.c | 56bb3008e56d01cbdb256bd9c3fec537d844cafc017ad46849a52666db6edf04 |
| src/bip39.c | src/bip39.c | 09748c332229dae846768186bd25654d6096a440ac70c186821da6a612b6e4b4 |
| src/bip39_wordlist.h | src/bip39_wordlist.h | 8cdf8e0f0aebc22a196291964a0a685072d48bc78e04463940bf714240b5cff9 |
| src/bolt11.c | src/bolt11.c | d4155441f14ca06f14807be261a6f2e96bd31edca9d22c1697205b98baa2f853 |
| src/crypto_aead.c | src/crypto_aead.c | 772a507379b3f7b007a6cce7a1ee84c530106c387ffe06e41239c2f8c1338596 |
| src/dw_state.c | src/dw_state.c | 27d7741cbb2799436846c1fe3c4f3da7eb0885b7393937ad08cdaeb123f634b1 |
| src/factory.c | src/factory.c | f1928bb0e37977923b2918521b1d41c2792dbaa8e2a42a2040eeb6e414e75949 |
| src/fee.c | src/fee.c | 1bdc07b738759870969f10b2f2e424092af1c8953735f6c093744f3ab6d89d29 |
| src/fee_estimator_static.c | src/fee_estimator_static.c | 1039ed51f7a47a5c48b6237562f91175e0dd506312f646ff3414c29d5e577937 |
| src/hd_key.c | src/hd_key.c | 671b0d968b965742e5762395686cf4dbe5c87895e5df8d1edb3f6ced92cc78cb |
| src/htlc_fee_bump.c | src/htlc_fee_bump.c | e9a861767543d523599b80b163c1068d6fd60f4c09ebbe6598df6c8eb83e2517 |
| src/ladder.c | src/ladder.c | ebb1f6fbaa1c83ec51599c435b74181935c207688d50d5e64c901914ef1ae0e6 |
| src/musig.c | src/musig.c | 576bc0903fb72b2015010b6d91089e689719b9a38a6255909cc36da039ea85e7 |
| src/shachain.c | src/shachain.c | ac40525991c58cf63de5e2ae7f5a7bebad8a7b129055c0cdd990646f1c1b84b7 |
| src/tapscript.c | src/tapscript.c | 192b1d26a495a51974bd96b87e74e6d9911bb4fe4128662e93be08614a33e188 |
| src/tx_builder.c | src/tx_builder.c | 37331eca72bf42c9821ad25159649e0a6a6011c91946478b1646590ff0cac045 |
| src/util.c | src/util.c | e3dd642fd4a5b19fca9976aafd1e35a9e178100d38e3c8b6ea1ad2f66acf64db |
| LICENSE | LICENSE | 0e9630e6a0a088e988aff20eed0bce3dba695e716ca5390e861ca748947c282b |
