# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.28**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B22J | Strike Witches 2 - Iyasu, Naosu, Punipuni Suru | Japan | Overlay 0 |
| B2JJ | Dragon Quest Monsters - Joker 2 Professional | Japan | Overlay 4 |
| B5FJ | Fuurai no Shiren 5 - Fortun Tower to Unmei no Dice | Japan | Overlay 176 |
| B6TE | Tangled | USA | Overlay 0 |
| B6TP | Tangled | Europe | Static region |
| B6TX | Tangled | Europe | Static region |
| B7KJ | Tamagotch no Narikiri Challenge | Japan | Overlay 41 |
| BDYD | Call of Duty - Black Ops | Germany | Overlay 3 |
| BDYE | Call of Duty - Black Ops | USA | Overlay 3 |
| BDYF | Call of Duty - Black Ops | France | Overlay 3 |
| BDYP | Call of Duty - Black Ops | Europe | Overlay 3 |
| BDYY | Call of Duty - Black Ops | Europe | Overlay 3 |
| BGTE | Ghost Trick - Phantom Detective | USA | Overlay 0 |
| BGTP | Ghost Trick - Phantom Detective | Europe | Overlay 0 |
| BJ8P | Cooking Mama World - Hobbies & Fun | Europe | Overlay 0 |
| BJCE | GoldenEye 007 | USA | Overlay 4 |
| BJCF | GoldenEye 007 | France | Overlay 4 |
| BJCI | GoldenEye 007 | Italy | Overlay 4 |
| BJCP | GoldenEye 007 | Europe | Overlay 4 |
| BK9E | Kingdom Hearts - Re-Coded | USA | Overlay 104 |
| BK9J | Kingdom Hearts Re-Coded | Japan | Overlay 104 |
| BK9P | Kingdom Hearts - Re-Coded | Europe | Overlay 104 |
| BO9J | Penguin no Mondai - The World | Japan | Overlay 0 |
| BOEJ | Inazuma Eleven 3 - Sekai heno Chousen! The Ogre | Japan | Overlay 129 |
| BOJD | One Piece - Gigant Battle | Germany | Overlay 24 |
| BOJF | One Piece - Gigant Battle | France | Overlay 24 |
| BOJP | One Piece - Gigant Battle | Europe | Overlay 24 |
| BQ8E | Crafting Mama | USA | Overlay 0 |
| BQ8J | Craft Mama | Japan | Overlay 0 |
| BQJJ | Kawaii Koneko DS 3 | Japan | Overlay 0 |
| BRIJ | Nori Nori Relaxuma - Hit Song Ongakusai | Japan | Overlay 0 |
| BRJE | Radiant Historia | USA | Overlay 0 |
| BRWJ | Super Robot Taisen L | Japan | Overlay 0 |
| BSDE | Lufia - Curse of the Sinistrals | USA | Overlay 0 |
| BUKJ | Rekishi Taisen Gettenka - Tenkaichi Battle Royal | Japan | Overlay 5 |
| BVIJ | Do-Konjou Shougakussei - Bon Bita - Hadaka no Choujou Ketsusen!! Bita vs. Dokuro Dei! | Japan | Overlay 5 |
| BVNE | Michael Jackson - The Experience | USA | Overlay 7 |
| BVNP | Michael Jackson - The Experience | Europe | Overlay 7 |
| BW4E | Wizards of Waverly Place - Spellbound | USA | Overlay 1 |
| BW4P | Wizards of Waverly Place - Spellbound | Europe | Overlay 1 |
| BXSE | Sonic Colors | USA | Overlay 17 |
| BXSJ | Sonic Colors | Japan | Overlay 17 |
| BXSP | Sonic Colours | Europe | Overlay 17 |
| BZBJ | Zombi Daisuki | Japan | Overlay 14 |
| BZQJ | Zac to Ombra - Maboroshi no Yuuenchi | Japan | Overlay 2 |
| C3JD | Professor Layton und die Verlorene Zukunft | Germany | Overlay 10 |
| C3JE | Professor Layton and the Unwound Future | USA | Overlay 10 |
| C3JF | Professeur Layton et le Destin Perdu | France | Overlay 10 |
| C3JH | Professor Layton en de Verloren Toekomst | Netherlands | Overlay 10 |
| C3JI | Professor Layton e il Futuro Perduto, Il | Italy | Overlay 10 |
| C3JP | Professor Layton and the Lost Future | Europe | Overlay 10 |
| C3JS | Profesor Layton y el Futuro Perdido, El | Spain | Overlay 10 |
| CJRE | Dragon Quest Monsters - Joker 2 | USA | Overlay 2 |
| CJRP | Dragon Quest Monsters - Joker 2 | Europe | Overlay 2 |
| CL4K | Zzang-Gu Rubber Clay | Korea | Overlay 0 |
| CNSE | Naruto Shippuden - Naruto vs Sasuke | USA | Overlay 0 |
| V2GE | Mario vs. Donkey Kong - Mini-Land Mayhem! (v01) | USA | Overlay 15 |
| V2GJ | Mario vs. Donkey Kong - Totsugeki! Mini-Land | Japan | Overlay 15 |
| V2GV | Mario vs. Donkey Kong - Mini-Land Mayhem | Europe | Overlay 15 |
| VKHE | Brainstorm Series - Treasure Chase | USA | Overlay 2 |
| VKHP | Know How 2 | Europe | Overlay 2 |
| VPLJ | Power Pro Kun Pocket 13 | Japan | Overlay 32 |
| VS3E | The Sims 3 | USA | Overlay 2 |
| VS3V | The Sims 3 | Europe | Overlay 2 |
| VTEE | Tron Evolution | USA | Overlay 2 |
| VTEV | Tron Evolution | Europe | Overlay 0 |
| VTEX | Tron Evolution | Europe | Overlay 0 |
| YEED | Inazuma Eleven | Germany | Overlay 90 |
| YEEF | Inazuma Eleven | France | Overlay 90 |
| YEEI | Inazuma Eleven | Italy | Overlay 90 |
| YEEP | Inazuma Eleven | Europe | Overlay 90 |
| YEES | Inazuma Eleven | Spain | Overlay 90 |
| YVIE | Dragon Quest VI - Realms of Revelation | USA | Overlay 47 |
| YVIP | Dragon Quest VI - Realms of Reverie | Europe | Overlay 47 |
