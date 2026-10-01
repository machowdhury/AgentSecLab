# Memory ownership and isolation

A memory id names a record. It does not name the owner. In this packet the owner is `user-a` and the writer is `acme-agent-memory-001`. ATTACK and RETEST both ask as `user-b`. ATTACK returns the record. RETEST isolates it. BASELINE is the owner reading their own record.

Recall is not a tool decision. Deletion and retention are NOT MEASURED.

## What I should now be able to explain

1. Why is a write not ownership?
2. Why is recall not authorization?
3. Why can the same agent still cross users?
4. What is the same in ATTACK and RETEST?
5. Why is owner recall not a tool grant?
6. Why is deletion NOT MEASURED?
7. Why is historical CTRL-MEMORY-CONTEXT-001 not an ownership decision?
