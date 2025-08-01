# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version 2.01, as it appears in these games (but likely several more):
- Golden Sun: Dark Dawn (US) as overlay 334
- Kirby Mass Attack (US and Japan) as overlay 28
- Cars 2 (US) as overlay 2
- Super Kaseki Horide (Japan) as overlay 15
- Harry Potter and the Deathly Hallows - Part 2 (US) as overlay 2
- Jewels of the Ages (US) as overlay 0
- Murder In Venice (US and EU) as overlay 8
- The Smurfs (US) as overlay 0
- Yu-Gi-Oh! 5D's World Championship 2011: Over the Nexus (US) as overlay 47
- Phineas and Ferb: Across the 2nd Dimension (US) as overlay 1
- Puyo Puyo!! 20th Anniversary (Japan) as overlay 15
- Shin Megami Tensei - Devil Survivor 2 (US and Japan) as overlay 6
- Harvest Moon DS: The Tale Of Two Towns (US) as overlay 5

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/VeHlh).
