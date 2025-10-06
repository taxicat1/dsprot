# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **2.03**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| B6KP | Tinker Bell - 2 Disney Games | Europe | Overlay 46 |
| BEBD | Inazuma Eleven 2 - Eissturm | Germany | Overlay 97 |
| BEBF | Inazuma Eleven 2 - Tempete de Glace | France | Overlay 97 |
| BEBI | Inazuma Eleven 2 - Bufera di Neve | Italy | Overlay 97 |
| BEBP | Inazuma Eleven 2 - Blizzard | Europe | Overlay 97 |
| BEBS | Inazuma Eleven 2 - Ventisca Eterna | Spain | Overlay 97 |
| BEED | Inazuma Eleven 2 - Feuersturm | Germany | Overlay 97 |
| BEEF | Inazuma Eleven 2 - Tempete de Feu | France | Overlay 97 |
| BEEI | Inazuma Eleven 2 - Tempesta di Fuoco | Italy | Overlay 97 |
| BEEP | Inazuma Eleven 2 - Firestorm | Europe | Overlay 97 |
| BEES | Inazuma Eleven 2 - Tormenta de Fuego | Spain | Overlay 97 |
| BKQE | Pucca - Power Up | USA | Overlay 0 |
| BKUP | Harvest Moon - The Tale of Two Towns | Europe | Overlay 4 |
| BLFD | Professor Layton und der Ruf des Phantoms | Germany | Overlay 3 |
| BLFE | Professor Layton and the Last Specter | USA | Overlay 3 |
| BLFF | Professeur Layton et l'Appel du Spectre | France | Overlay 3 |
| BLFH | Professor Layton en de Melodie van het Spook | Netherlands | Overlay 3 |
| BLFI | Professor Layton e il Richiamo dello Spettro, Il | Italy | Overlay 3 |
| BLFP | Professor Layton and the Spectre's Call | Europe | Overlay 3 |
| BLFS | Profesor Layton y la Llamada del Espectro, El | Spain | Overlay 3 |
| BRZE | Beyblade - Metal Masters | USA | Overlay 0 |
| BRZP | Beyblade - Metal Masters - Nightmare Rex | Europe | Overlay 0 |
| BXPJ | Winnie the Pooh - 100 Acre no Mori no Cooking Book | Japan | Overlay 38 |
| CLJK | Mario & Luigi RPG 3 - Koopa's Inside Adventure | Korea | Overlay 138 |
| CLPD | Club Penguin - Elite Penguin Force | Germany | Overlay 1 |
| TBSJ | Byoutai Seiri DS - Image Dekiru! Shikkan, Shoujou to Care | Japan | Overlay 0 |
| TCME | Camping Mama - Outdoor Adventures | USA | Overlay 0 |
| TCMJ | Camping Mama Plus Papa | Japan | Overlay 0 |
| TCMP | Cooking Mama World - Outdoor Adventures | Europe | Overlay 0 |
| TGBJ | One Piece - Gigant Battle 2 - Shin Sekai | Japan | Overlay 36 |
| TGCJ | Tamagotchi Collection | Japan | Overlay 0 |
| TJ7J | New Horizon English Course 3 | Japan | Overlay 0 |
| TJ8J | New Horizon English Course 2 | Japan | Overlay 0 |
| TJ9J | New Horizon English Course 1 | Japan | Overlay 0 |
| TK2J | Kaidan Restaurant - Zoku! Shin Menu 100-Sen | Japan | Overlay 0 |
| TKDJ | Ore-Sama Kingdom - Koi mo Manga mo Debut o Mezase! Doki Doki Love Lesson | Japan | Overlay 0 |
| TMXJ | Metal Max 2 - Reloaded | Japan | Overlay 0 |
| TPQJ | Suite PreCure - Melody Collection | Japan | Overlay 44 |
| VCDE | Solatorobo - Red the Hunter | USA | Overlay 4 |
| VDEE | Fossil Fighters - Champions | USA | Overlay 15 |
| VEBJ | RPG Tsukuru DS+ - Create the New World | Japan | Overlay 0 |
| VP4J | Power Pro Kun Pocket 14 | Japan | Overlay 32 |
| VPYJ | Pokemon Plus - Nobunaga no Yabou | Japan | Overlay 9 |
| VTPV | Phineas and Ferb - 2 Disney Games | Europe | Overlay 85 |
| YMPJ | MapleStory DS | Japan | Overlay 107 |
