# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is likely version 1.26 (unconfirmed), as it appears these games (but likely appears in several more):
- Tetris Party Deluxe (USA) as overlay 1
- Megaman Zero Collection (USA and Japan) as overlay 8
- Art Academy (USA and Japan) as overlay 0
- Toy Story 3 (USA) as overlay 0
- Phineas and Ferb - Ride Again (USA) as overlay 5
- Camp Rock: The Final Jam (USA) as overlay 42
- Harry Potter and the Deathly Hallows Part 1 (USA and EU) as overlay 2
- MySims: SkyHeros (USA and EU) as overlay 2
- Super Scribblenauts (USA) as overlay 20
- Club Penguin: Elite Penguin Force - Herbert's Revenge (USA) as overlay 11
- Dragon Quest Monsters: Joker 2 (Japan) as overlay 2
- Lost Identities (EU) as overlay 2

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/I41ac).
