use oversight_semantic::{embed_synonyms, verify_synonyms, iter_matchable_words};

const TEXT: &str = "Q3 revenue performance exceeded expectations across all business units. \
The team plans to continue the expansion strategy outlined in our report at \
https://internal.example.com/q3-2026.pdf and will begin hiring in \
/home/claude/hiring_plan.docx this month. However, there are important risks \
to consider before we commence the next phase.";

fn main() {
    let mark_a = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
    let mark_b: &[u8] = b"\xde\xad\xbe\xef\xfe\xed\xfa\xce";

    for (name, mark) in [("A", &mark_a[..]), ("B", mark_b)] {
        let marked = embed_synonyms(TEXT, mark, 5);
        let matches_before = iter_matchable_words(TEXT).len();
        let matches_after = iter_matchable_words(&marked).len();
        let (ok, score) = verify_synonyms(&marked, mark, 0.70);
        println!("mark {}: matches before={} after={}, verify ok={} score={:.3}",
                 name, matches_before, matches_after, ok, score);

        // Print the first few matches before/after
        let before: Vec<_> = iter_matchable_words(TEXT).iter().take(10)
            .map(|m| (m.orig_word.clone(), m.class_index, m.variant_index)).collect();
        let after: Vec<_> = iter_matchable_words(&marked).iter().take(10)
            .map(|m| (m.orig_word.clone(), m.class_index, m.variant_index)).collect();
        println!("  first 10 before: {:?}", before);
        println!("  first 10 after:  {:?}", after);
    }
}
