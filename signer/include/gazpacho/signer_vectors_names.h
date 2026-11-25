/* The vectors build's names (review A of #71, H3; decision K20).
 *
 * gazpacho_signer_vectors is the only build that accepts fresh = 0 (BIP 340's
 * all-zero aux_rand), for byte-exact test vectors. Compiled with
 * GZ_SG_VECTORS, every entry point of the signer takes another name, so a
 * program written against the production names cannot link against it: a
 * stray link fails to resolve instead of silently signing with fixed aux.
 * The build also exports gz_sg_vectors_build_never_ship, which CTest's
 * signer_link_guard requires absent from the production library.
 * tools/check-signer-boundary.sh refuses GZ_SG_VECTORS outside signer/. */
#ifndef GAZPACHO_SIGNER_VECTORS_NAMES_H
#define GAZPACHO_SIGNER_VECTORS_NAMES_H
#define gz_signer_size gz_sgv_signer_size
#define gz_signer_init gz_sgv_signer_init
#define gz_signer_wipe gz_sgv_signer_wipe
#define gz_sg_kind_allowed gz_sgv_kind_allowed
#define gz_sg_purposes gz_sgv_purposes
#define gz_sg_may_sign_tag gz_sgv_may_sign_tag
#define gz_sg_host_pub gz_sgv_host_pub
#define gz_sg_slot_add gz_sgv_slot_add
#define gz_sg_slot_drop gz_sgv_slot_drop
#define gz_sg_gate_open gz_sgv_gate_open
#define gz_sg_gate_close gz_sgv_gate_close
#define gz_sg_gate_close_all gz_sgv_gate_close_all
#define gz_sg_seat_key gz_sgv_seat_key
#define gz_sg_sign_envelope gz_sgv_sign_envelope
#define gz_sg_sign_terms gz_sgv_sign_terms
#define gz_sg_sign_binding gz_sgv_sign_binding
#define gz_sg_round_open gz_sgv_round_open
#define gz_sg_nonce gz_sgv_nonce
#define gz_sg_partial gz_sgv_partial
#define gz_sg_round_close gz_sgv_round_close
#define gz_sg_ecdh gz_sgv_ecdh
#define gz_sg_fund_plan gz_sgv_fund_plan
#define gz_sg_fund_sign gz_sgv_fund_sign
#define gz_sg_fund_spend_back gz_sgv_fund_spend_back
#define gz_sg_fund_adopt gz_sgv_fund_adopt
#define gz_sg_fund_release gz_sgv_fund_release
#define gz_sg_spend_back_fee_cap gz_sgv_spend_back_fee_cap
#endif
