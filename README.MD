# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is likely version 1.28 (unconfirmed), as it appears in these games (but likely several more):
- GoldenEye 007 (US) as overlay 4
- Wizards Of Waverly Place: Spellbound (US) as overlay 1
- Treasure Chase (US) as overlay 2
- Cooking Mama World: Hobbies and Fun as overlay 0
- Radiant Historia (US) as overlay 0
- Call of Duty: Black Ops (US) as overlay 3
- Lufia - Curse of the Sinistrals (US) as overlay 0
- Mario vs Donkey Kong: Mini Land Mayhem (US and Japan) as overlay 15
- Naruto Shippuden - Naruto vs Sasuke (US) as overlay 0
- Professor Layton and the Unwound Future (US) as overlay 10
- Sonic Colors (US and Japan) as overlay 17
- Tron: Evolution (US) as overlay 2
- Kingdom Hearts - Re-coded (US and Japan) as overlay 104
- Dragon Quest Monsters: Joker 2 (US) as overlay 2

(Plus several other Japan-exclusive titles).

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Supposedly, at least 500 DS titles use DS Protect in some form.

For instructions to build the library see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## TODO

- Verify it actually works with Wine.
- Decompile the last function (`Encryptor_EncryptFunction` @ https://decomp.me/scratch/D8nhP).
