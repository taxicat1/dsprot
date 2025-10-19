# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.26**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| AZLK | My Fashion - Girls Style | Korea | Overlay 155 |
| B2AK | Aranuri | Korea | Overlay 0 |
| B2BJ | Captain Tsubasa - Gekitou no Kiseki | Japan | Overlay 84 |
| B2BX | Captain Tsubasa - New Kick Off | Europe | Overlay 85 |
| B2YK | Piyodamari DS | Korea | Overlay 0 |
| B4TE | Tetris Party Deluxe | USA | Overlay 1 |
| B4TP | Tetris Party Deluxe | Europe | Overlay 1 |
| B6ZE | MegaMan Zero Collection | USA | Overlay 8 |
| B6ZJ | RockMan Zero Collection | Japan | Overlay 8 |
| B6ZP | MegaMan Zero Collection | Europe | Overlay 8 |
| B7HE | Harry Potter and the Deathly Hallows - Part 1 | USA | Overlay 2 |
| B7HP | Harry Potter and the Deathly Hallows - Part 1 | Europe | Overlay 2 |
| B7XJ | Seitokai no Ichizon - DS Suru Seitokai | Japan | Overlay 0 |
| BFLE | MySims - SkyHeroes | USA | Overlay 2 |
| BFLP | MySims - SkyHeroes | Europe | Overlay 2 |
| BG3J | G.G Series Collection+ | Japan | Overlay 82 |
| BG5J | Tamagotchi no Pichi Pichi Omisecchi | Japan | Overlay 17 |
| BGTJ | Ghost Trick | Japan | Overlay 0 |
| BH2E | Super Scribblenauts | USA | Overlay 20 |
| BH2P | Super Scribblenauts | Europe | Overlay 20 |
| BH2X | Super Scribblenauts | Europe | Overlay 20 |
| BJKJ | Ippan Zaidan Houjin - Nihon Kanji Shuujukudo Kentei Kikou Kounen - Tsuutenkaku DS | Japan | Overlay 7 |
| BLLE | Petz - Catz Playground | USA | Overlay 0 |
| BOBJ | Kaidan Restaurant - Ura Menu 100-Sen | Japan | Overlay 0 |
| BQPK | Figure Princess | Korea | Static region |
| BQWJ | Medarot DS - Kuwagata Ver. | Japan | Overlay 2 |
| BROJ | Super Robot Taisen OG Saga - Masou Kishin - The Lord of Elemental | Japan | Overlay 6 |
| BS8E | The Sorcerer's Apprentice | USA | Overlay 0 |
| BS8P | The Sorcerer's Apprentice | Europe | Overlay 0 |
| BSWJ | Saka Tsuku DS - World Challenge 2010 | Japan | Overlay 3 |
| BYMJ | Yumeiro Patissiere - My Sweets Cooking | Japan | Overlay 100 |
| BYXK | Yu-Gi-Oh! 5D's - World Championship 2010 - Reverse of Arcadia | Korea | Overlay 41 |
| C6OJ | Medarot DS - Kabuto Ver. | Japan | Overlay 2 |
| CJRJ | Dragon Quest Monsters - Joker 2 | Japan | Overlay 2 |
| CVAJ | Tokyo Twilight Busters - Kindan no Ikenie Teito Jigokuhen | Japan | Static region |
| CY9E | Club Penguin - EPF - Herbert's Revenge | USA | Overlay 11 |
| CY9P | Club Penguin - EPF - Herbert's Revenge | Europe | Overlay 11 |
| UXBP | Jam with the Band | Europe | Overlay 0 |
| VAAJ | Egokoro Kyoushitsu DS | Japan | Overlay 0 |
| VAAE | Art Academy | USA | Overlay 0 |
| VAAK | Art Academy | Korea | Overlay 0 |
| VAAV | Art Academy | Europe | Overlay 0 |
| VCME | Camp Rock - The Final Jam | USA | Overlay 42 |
| VCMP | Camp Rock - The Final Jam | Europe | Overlay 42 |
| VCMV | Camp Rock - The Final Jam | Europe | Overlay 42 |
| VCPJ | Cosmetick Paradise - Kirei no Mahou | Japan | Overlay 0 |
| VL3J | Elminage II DS Remix - Sousei no Megami to Unmai no Daichi | Japan | Overlay 0 |
| VLIP | Lost Identities | Europe | Overlay 0 |
| VPFE | Phineas and Ferb - Ride Again | USA | Overlay 5 |
| VT3E | Toy Story 3 | USA | Overlay 2 |
| VT3J | Toy Story 3 | Japan | Overlay 0 |
| VT3V | Toy Story 3 | Europe | Overlay 0 |
| VT3X | Toy Story 3 | Europe | Overlay 0 |
| YBNE | 100 Classic Books | USA | Overlay 9 |
| YDQE | Dragon Quest IX - Sentinels of the Starry Skies | USA | Overlay 29 |
| YDQP | Dragon Quest IX - Sentinels of the Starry Skies | Europe | Overlay 29 |
| YROK | Princess in Wonderland | Korea | Overlay 0 |
