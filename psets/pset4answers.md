CS 161 Problem Set 4 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset4collab.md`.

Answers to written questions
----------------------------

Eviction plan

I use a basic LRU cache to 
I keep a eviction_queue_, which contains all elements that are guaranteed to have a zero ref count, and can safely be evicted. Any time a block is loaded while it's on the eviction queue, I remove it from the eviction queue since it was recently accessed. New entries are added to the front, and the potential evictions are taken from the back of the queue.


Grading notes
-------------
