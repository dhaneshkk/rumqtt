/-!
# Hybrid key-combiner spec for pqmqtt

Models the combiner used in BOTH layers:
* Layer 1 — TLS 1.3 group X25519MLKEM768 (RFC 10024): the shared secret is
  `ss_mlkem ‖ ss_x25519` (ML-KEM first), fed to the TLS key schedule (HKDF).
* Layer 2 — `rumqtt-pq-envelope` (`src/lib.rs`: `combiner_ikm` / `derive_key`):
  `ikm = ss_mlkem ‖ ss_x25519`, `key = HKDF-SHA256(salt, ikm, info)` with
  `info = LABEL ‖ kem_ct ‖ eph_pub ‖ topic ‖ sender ‖ seq`.

## Proven here (Lean 4 core only, no `sorry`, axioms printed at the end)
1. `combine_length`      : the IKM is always 64 bytes.
2. `split_combine`       : the IKM decodes uniquely back to its two halves.
3. `combine_injective`   : jointly injective.
4. `combine_inj_pq` / `combine_inj_ec` : injective in EACH component with the
   other held fixed — the classical secret can never cancel or collapse the
   post-quantum one, and vice versa (structural "either-component" property).
5. `kdf_robust_pq` / `kdf_robust_ec` : for ANY injective KDF model `H`, the
   derived key is still injective in each component.
6. `kdf_binds_info`      : with the secrets fixed, distinct `info`
   (ciphertexts, topic, sender, seq) give distinct keys — context binding.
7. `no_entropy_loss_pq`  : mapping a duplicate-free set of PQ secrets through the
   combiner (any fixed classical secret) stays duplicate-free, so the key
   space is no smaller than the PQ secret space.
8. `props_consistent_sound` / `props_consistent_nil` : the MQTT 5 user-property
   check (`Opener::open_with_properties`) only passes if every `pqe-*` property
   received is exactly one the signed header produced; no properties always passes.

## Assumed, NOT proven here (computational)
IND-CCA security of the hybrid needs: ML-KEM-768 IND-CCA2 (FIPS 203),
X25519 gap-DH, and HKDF as a PRF / random oracle — the standard
concatenate-then-KDF robustness argument (Giacon–Heuer–Poettering 2018;
X-Wing analysis). Real HKDF is not injective; `H` below is the idealised model.
-/

namespace PqMqtt

abbrev Bytes := List UInt8

/-- A 32-byte shared secret (ML-KEM-768 and X25519 both produce 32 bytes). -/
abbrev Secret32 := { b : Bytes // b.length = 32 }

/-- The hybrid combiner: ML-KEM secret first, then X25519 (RFC 10024 order). -/
def combine (pq ec : Secret32) : Bytes := pq.val ++ ec.val

/-- Inverse of `combine`. -/
def split (b : Bytes) : Bytes × Bytes := (b.take 32, b.drop 32)

theorem combine_length (pq ec : Secret32) : (combine pq ec).length = 64 := by
  simp [combine, pq.property, ec.property]

theorem split_combine (pq ec : Secret32) :
    split (combine pq ec) = (pq.val, ec.val) := by
  have h := pq.property
  simp [split, combine, ← h]

theorem combine_injective {a b c d : Secret32}
    (h : combine a b = combine c d) : a = c ∧ b = d := by
  have hs := congrArg split h
  rw [split_combine, split_combine] at hs
  injection hs with h1 h2
  exact ⟨Subtype.ext h1, Subtype.ext h2⟩

theorem combine_inj_pq (ec : Secret32) :
    Function.Injective (fun pq => combine pq ec) :=
  fun _ _ h => (combine_injective h).1

theorem combine_inj_ec (pq : Secret32) :
    Function.Injective (fun ec => combine pq ec) :=
  fun _ _ h => (combine_injective h).2

/-- Idealised KDF model: `H (ikm, info)`, assumed injective. -/
theorem kdf_robust_pq {α : Type} (H : Bytes × Bytes → α) (hH : Function.Injective H)
    (ec : Secret32) (info : Bytes) :
    Function.Injective (fun pq => H (combine pq ec, info)) := by
  intro a b h
  have := hH h
  injection this with h1
  exact combine_inj_pq ec h1

theorem kdf_robust_ec {α : Type} (H : Bytes × Bytes → α) (hH : Function.Injective H)
    (pq : Secret32) (info : Bytes) :
    Function.Injective (fun ec => H (combine pq ec, info)) := by
  intro a b h
  have := hH h
  injection this with h1
  exact combine_inj_ec pq h1

theorem kdf_binds_info {α : Type} (H : Bytes × Bytes → α) (hH : Function.Injective H)
    (pq ec : Secret32) :
    Function.Injective (fun info => H (combine pq ec, info)) := by
  intro a b h
  have := hH h
  injection this

theorem no_entropy_loss_pq (ec : Secret32) (S : List Secret32) (hS : S.Nodup) :
    (S.map (fun pq => combine pq ec)).Nodup := by
  unfold List.Nodup at *
  exact List.Pairwise.map _ (fun a b hab h => hab (combine_inj_pq ec h)) hS

/-- MQTT 5 user-property check: every property whose key satisfies `isPqe` must
appear verbatim among the properties derived from the signed envelope header. -/
def propsConsistent (isPqe : String → Bool) (expected props : List (String × String)) : Bool :=
  props.all (fun kv => !isPqe kv.1 || expected.contains kv)

theorem props_consistent_sound (isPqe : String → Bool) (expected props : List (String × String))
    (h : propsConsistent isPqe expected props = true) :
    ∀ kv ∈ props, isPqe kv.1 = true → kv ∈ expected := by
  intro kv hmem hp
  have hall := List.all_eq_true.mp h kv hmem
  simp [hp] at hall
  exact hall

theorem props_consistent_nil (isPqe : String → Bool) (expected : List (String × String)) :
    propsConsistent isPqe expected [] = true := rfl

/-- Concrete sanity check, evaluated by the kernel. -/
example : (combine ⟨List.replicate 32 1, by simp⟩ ⟨List.replicate 32 2, by simp⟩).length = 64 :=
  combine_length _ _

end PqMqtt

#print axioms PqMqtt.split_combine
#print axioms PqMqtt.combine_injective
#print axioms PqMqtt.kdf_robust_pq
#print axioms PqMqtt.kdf_robust_ec
#print axioms PqMqtt.kdf_binds_info
#print axioms PqMqtt.no_entropy_loss_pq
#print axioms PqMqtt.props_consistent_sound
