/-!
# Hybrid key-combiner spec for pqmqtt

Models the ML-KEM-first hybrid combiner used in BOTH layers:
* Layer 1 — TLS 1.3 group X25519MLKEM768 (RFC 10024): the shared secret is
  `ss_mlkem ‖ ss_x25519`, fed to the TLS key schedule (HKDF).
* Layer 2 — HPKE (RFC 9180) with the X-Wing KEM (`src/suite.rs`): X-Wing derives
  `SHA3-256(ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ label)`, i.e. `combine`
  followed by a fixed-length context, which is `combineCtx` below; HPKE's key schedule
  then binds `info` (topic, sender, seq / session ids).

Also models session mode (`src/session.rs`): bucket padding (`bucketFor`, `padBody`) and
the sliding replay window (`Window`).

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
9. `combineCtx_inj_pq` / `combineCtx_inj_ec` : appending X-Wing's fixed context
   (ct_X ‖ pk_X ‖ label) keeps injectivity in each secret.
10. `bucketFor_ge` / `padBody_length` / `unpad_padBody` / `same_bucket_same_length`:
   the padded block is never shorter than the input, its length is exactly the bucket,
   the payload is recovered, and two payloads in the same bucket have equal length.
11. `window_no_double_accept` : a frame accepted once is never accepted again.

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

/-! ## X-Wing context (Layer 2 via HPKE) -/

/-- `combine` followed by X-Wing's fixed context `ct_X ‖ pk_X ‖ label`. -/
def combineCtx (pq ec : Secret32) (ctx : Bytes) : Bytes := combine pq ec ++ ctx

theorem combineCtx_inj_pq (ec : Secret32) (ctx : Bytes) :
    Function.Injective (fun pq => combineCtx pq ec ctx) := by
  intro a b h
  exact combine_inj_pq ec (List.append_cancel_right h)

theorem combineCtx_inj_ec (pq : Secret32) (ctx : Bytes) :
    Function.Injective (fun ec => combineCtx pq ec ctx) := by
  intro a b h
  exact combine_inj_ec pq (List.append_cancel_right h)

/-! ## Session mode: bucket padding (`bucket_for`, `pad`, `unpad`) -/

/-- First bucket `≥ n`, else `n` rounded up to a multiple of `m` (the largest bucket). -/
def bucketFor (bs : List Nat) (m n : Nat) : Nat :=
  match bs.find? (fun b => decide (n ≤ b)) with
  | some b => b
  | none => n + (m - n % m) % m

theorem bucketFor_ge (bs : List Nat) (m n : Nat) : n ≤ bucketFor bs m n := by
  unfold bucketFor
  split
  · rename_i b hb
    have := List.find?_some hb
    simpa using this
  · exact Nat.le_add_right _ _

/-- Encrypted block body after the 4-byte length prefix: payload then zero padding. -/
def padBody (bs : List Nat) (m : Nat) (data : Bytes) : Bytes :=
  data ++ List.replicate (bucketFor bs m (data.length + 4) - (data.length + 4)) 0

theorem padBody_length (bs : List Nat) (m : Nat) (data : Bytes) :
    (padBody bs m data).length + 4 = bucketFor bs m (data.length + 4) := by
  have h := bucketFor_ge bs m (data.length + 4)
  simp [padBody]
  omega

theorem unpad_padBody (bs : List Nat) (m : Nat) (data : Bytes) :
    (padBody bs m data).take data.length = data := by
  simp [padBody]

theorem same_bucket_same_length (bs : List Nat) (m : Nat) (d1 d2 : Bytes)
    (h : bucketFor bs m (d1.length + 4) = bucketFor bs m (d2.length + 4)) :
    (padBody bs m d1).length = (padBody bs m d2).length := by
  have h1 := padBody_length bs m d1
  have h2 := padBody_length bs m d2
  omega

/-! ## Session mode: sliding replay window (`Window::check` / `Window::mark`) -/

/-- Abstract window: highest accepted seq and the set of accepted seqs still tracked. -/
structure Window where
  highest : Nat
  seen : List Nat

def Window.check (w : Window) (s : Nat) : Bool :=
  s ≠ 0 && (decide (w.highest < s) || (decide (w.highest - s < 64) && !w.seen.contains s))

def Window.mark (w : Window) (s : Nat) : Window :=
  { highest := max w.highest s, seen := s :: w.seen }

theorem window_no_double_accept (w : Window) (s : Nat) :
    (w.mark s).check s = false := by
  simp [Window.check, Window.mark]
  omega

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
#print axioms PqMqtt.combineCtx_inj_pq
#print axioms PqMqtt.bucketFor_ge
#print axioms PqMqtt.padBody_length
#print axioms PqMqtt.unpad_padBody
#print axioms PqMqtt.same_bucket_same_length
#print axioms PqMqtt.window_no_double_accept
