# dsprot

This is a decompilation of DS Protect, an antipiracy library for the Nintendo DS. This is version **1.23**. See below for a list of games that use this version, and see other branches for alternate versions.

See [dsdetect](https://github.com/taxicat1/dsdetect) to analyze a ROM file for DS Protect, as the lists here are not comprehensive.

This library is designed to detect if a DS game is running on an emulator or flashcart. What happens after it detects that is up to the game that is integrating it.

The existence, mechanics, and effects of DS Protect have been documented as early as 2009 ([link](https://gbatemp.net/threads/seeking-help-for-anti-piracy-protection-removal.134683/post-1768816), [link](https://sourceforge.net/p/desmume/bugs/979/), [link](https://opentrackers.org/scenerules.org/html/2010_NDSr.html)).

Over 300 DS titles are known to use DS Protect in some form.

For instructions to build the library, see [BUILD.MD](./BUILD.MD).

For documentation of its inner workings, see [FUNCTIONALITY.MD](./doc/FUNCTIONALITY.MD) (also [ENCODING.MD](./doc/ENCODING.MD) and [ASSEMBLY.MD](./doc/ASSEMBLY.MD)).

## Game list

| Serial | Title | Region | Location |
| --- | --- | --- | --- |
| ARFK | Rune Factory - A Fantasy Harvest Moon | Korea | Overlay 2 |
| ARMK | Mario & Luigi RPG Partners in Time | Korea | Overlay 28 |
| B2WJ | Moe Moe 2-ji Taisen (ryoku) Two - Yamato Nadeshiko | Japan | Overlay 0 |
| B35J | San Goku Shi DS 3 | Japan | Overlay 10 |
| B3RJ | Pokemon Ranger - Hikari no Kiseki | Japan | Overlay 0 |
| B4FJ | Fushigi no Dungeon - Fuurai no Shiren 4 - Kami no Hitomi to Akuma no Heso | Japan | Overlay 179 |
| B4NK | Princess Angel | Korea | Overlay 0 |
| B59J | Saku Saku Jinkou Kokyuu Care Training DS | Japan | Overlay 0 |
| B5GJ | Shin Sengoku Tenka Touitsu - Gunyuutachi no Souran | Japan | Overlay 0 |
| BBUJ | Metal Fight Beyblade - Bakutan! Cyber Pegasis | Japan | Overlay 22 |
| BBUK | Metal Fight BeyBlade - Cyber Pegasis | Korea | Overlay 20 |
| BD2E | Deca Sports DS | USA | Overlay 2 |
| BD2J | Deca Sporta - DS de Sports '10' Shumoku! | Japan | Overlay 2 |
| BD2P | Sports Island DS | Europe | Overlay 2 |
| BDBE | Dragon Ball - Origins 2 | USA | Overlays 2, 3 |
| BDBJ | Dragon Ball DS 2 - Totsugeki! Red Ribbon Gun | Japan | Overlays 2, 3 |
| BDBP | Dragon Ball - Origins 2 | Europe | Overlays 2, 3 |
| BDGJ | Dear Girl - Stories - Hibiki - Hibiki Tokkun Daisakusen! | Japan | Overlay 0 |
| BEKJ | 5-kyuu kara 1-kyuu Kanzen Taiou Saishin Kako Mondai - Nijishiken Taisaku - Eiken Kanzenban (v01) | Japan | Overlay 22 |
| BIPJ | Pen1 Grand Prix - Penguin no Mondai Special | Japan | Overlay 13 |
| BJ3E | Etrian Odyssey III - The Drowned City | USA | Overlay 5 |
| BJ3J | Sekaiju no Meikyuu III - Seikai no Raihousha | Japan | Overlay 5 |
| BK3J | Kawaii Koinu DS 3 | Japan | Overlay 18 |
| BKJJ | Nazotte Oboeru - Otona no Kanji Renshuu - Kaitei Ban | Japan | Overlay 7 |
| BKMJ | Rilakkuma Rhythm - Mattari Kibun de Dararan Ran | Japan | Overlay 3 |
| BKUJ | Bokujou Monogatari - Futago no Mura | Japan | Overlay 5 |
| BKXJ | Kaijuu Busters | Japan | Overlay 256 |
| BL3J | Lupin Sansei - Shijou Saidai no Zunousen | Japan | Overlay 29 |
| BLFJ | Layton Kyouju to Majin no Fue | Japan | Overlay 3 |
| BM7J | Gokujou!! Mecha Mote Iinchou - MM Town de Miracle Change! | Japan | Overlay 0 |
| BMTE | Shin Megami Tensei - Strange Journey | USA | Overlay 0 |
| BNCJ | Nodame Cantabile - Tanoshii Ongaku no Jikan Desu | Japan | Overlay 10 |
| BPOJ | Utacchi | Japan | Overlay 311 |
| BPPJ | PostPet DS - Yumemiru Momo to Fushigi no Pen | Japan | Overlay 78 |
| BPUJ | Nettou! Powerful Koushien | Japan | Overlay 35 |
| BQ2J | Quiz Magic Academy DS - Futatsu no Jikuuseki | Japan | Overlay 2 |
| BQ9J | Tekipaki Kyuukyuu Kyuuhen Training DS | Japan | Overlay 0 |
| BQBJ | Crayon Shin-chan - Obaka Dainin Den - Susume! Kasukabe Ninja Tai! | Japan | Overlay 48 |
| BQIJ | Cooking Idol I! My! Mine! - Game de Hirameki! Kirameki! Cooking | Japan | Overlay 0 |
| BRME | Rooms - The Main Building | USA | Overlay 0 |
| BRMJ | Rooms - Fushigi na Ugoku Heya | Japan | Overlay 0 |
| BRMP | Rooms - The Main Building | Europe | Overlay 0 |
| BRQJ | Gendai Daisenryaku DS - Isshoku Sokuhatsu, Gunji Balance Houkai | Japan | Overlay 0 |
| BSDJ | Estpolis - The Lands Cursed by the Gods | Japan | Overlay 0 |
| BT5J | TOEIC Test Super Coach at DS | Japan | Overlay 0 |
| BTAJ | Lina no Atelier - Strahl no Renkinjutsushi | Japan | Overlay 0 |
| BTGJ | Tennis no Ouji-sama - Motto Gakuensai no Ouji-sama - More Sweet Edition | Japan | Overlay 0 |
| BWCJ | Minna no Conveni | Japan | Static region |
| BWWJ | WiZmans World | Japan | Overlay 2 |
| BYNJ | Yamakawa Shuppansha Kanshuu - Shousetsu Nihonshi B - Shin Sougou Training Plus | Japan | Overlay 0 |
| BYSJ | Yamakawa Shuppansha Kanshuu - Shousetsu Sekaishi B - Shin Sougou Training Plus | Japan | Overlay 0 |
| BYXE | Yu-Gi-Oh! 5D's - World Championship 2010 - Reverse of Arcadia | USA | Overlay 41 |
| BYXJ | Yu-Gi-Oh! 5D's - World Championship 2010 - Reverse of Arcadia | Japan | Overlay 41 |
| BYXP | Yu-Gi-Oh! 5D's - World Championship 2010 - Reverse of Arcadia | Europe | Overlay 41 |
| C34J | Mini Yonku DS | Japan | Overlay 2 |
| C6FJ | Super Robot Taisen OG Saga - Mugen no Frontier EXCEED | Japan | Overlay 0 |
| CQ2J | Sengoku Spirits - Gunshiden | Japan | Overlay 1 |
| CQ3J | Sengoku Spirits - Moushou Den | Japan | Overlay 1 |
| CZXK | Touch Man to Man - Gicho Yeongeo | Korea | Overlay 0 |
| IPGD | Pokemon - Silberne Edition SoulSilver | Germany | Overlay 123 |
| IPGE | Pokemon - SoulSilver Version | USA | Overlay 123 |
| IPGE | Pokemon - SoulSilver Version (v10) | USA | Overlay 123 |
| IPGF | Pokemon Version Argent - SoulSilver | France | Overlay 123 |
| IPGI | Pokemon - Versione Argento SoulSilver | Italy | Overlay 123 |
| IPGK | Pokemon - SoulSilver | Korea | Overlay 123 |
| IPGS | Pokemon - Edicion Plata SoulSilver | Spain | Overlay 123 |
| IPKD | Pokemon - Goldene Edition HeartGold | Germany | Overlay 123 |
| IPKE | Pokemon - HeartGold Version | USA | Overlay 123 |
| IPKE | Pokemon - HeartGold Version (v10) | USA | Overlay 123 |
| IPKF | Pokemon Version Or - HeartGold | France | Overlay 123 |
| IPKI | Pokemon - Versione Oro HeartGold | Italy | Overlay 123 |
| IPKK | Pokemon - HeartGold | Korea | Overlay 123 |
| IPKS | Pokemon - Edicion Oro HeartGold | Spain | Overlay 123 |
| VALE | Alice in Wonderland | USA | Overlay 11 |
| VALV | Alice in Wonderland | Europe | Overlay 0 |
| VCGJ | Kirakira Rhythm Collection | Japan | Overlay 0 |
| VFBE | Petz Fantasy - Moonlight Magic | USA | Overlay 12 |
| VFZE | Petz Fantasy - Sunshine Magic | USA | Overlay 12 |
| VFZV | Petz Fantasy | Europe | Overlay 12 |
| VSNE | Sonny with a Chance | USA | Overlay 1 |
| VSNV | Sonny with a Chance | Europe | Overlay 1 |
| YBND | Bibliothek der Klassischen Buecher | Germany | Overlay 9 |
| YBNF | 100 Livres Classiques | France | Overlay 9 |
| YCUP | Nintendo Presents - Crossword Collection | Europe | Overlay 0 |
| YR4J | Sengoku Spirits - Shukun Den | Japan | Overlay 1 |
