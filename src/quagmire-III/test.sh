make

echo -------------------------------------------------------------------------------------------
echo Example from https://www.cryptogram.org/downloads/aca.info/ciphers/QuagmireIII.pdf
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo KRSLWMITJDVIABMRGQMTMLLIVIFUIXRHTNYONVRHHIIIRMCAOVEI
echo Actual ciphertext:
./quagmire encrypt 3 test-encrypt-quagmire-iii.txt AUTOMOBILE HIGHWAY

echo Expected plaintext: 
echo THESAMEKEYEDALPHABETISUSEDFORPLAINANDCIPHERALPHABETS
echo Actual plaintext:
./quagmire decrypt 3 test-decrypt-quagmire-iii.txt AUTOMOBILE HIGHWAY

echo
echo -------------------------------------------------------------------------------------------
echo K1 - Quagmire III
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD
echo Actual ciphertext:
./quagmire encrypt 3 test-K1-pt.txt KRYPTOS PALIMPSEST

echo Expected plaintext: 
echo BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION
echo Actual plaintext:
./quagmire decrypt 3 ../../ciphers/kryptos/K1.txt KRYPTOS PALIMPSEST

echo
echo -------------------------------------------------------------------------------------------
echo K2 - Quagmire III
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG
echo Actual ciphertext:
./quagmire encrypt 3 test-K2-pt.txt KRYPTOS ABSCISSA

echo Expected plaintext: 
echo ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS
echo Actual plaintext:
./quagmire decrypt 3 ../../ciphers/kryptos/K2.txt KRYPTOS ABSCISSA

# echo
# echo -------------------------------------------------------------------------------------------
# echo MA2016-E21 - Quagmire III
# echo -------------------------------------------------------------------------------------------
# echo Expected ciphertext: 
# echo ALXGDORKNIHGRLIRMTVTDIXQCWQKMICKZZFQGKHLXODBYOFWZLWDFZBNKRXYAFDLVBIQZYAEDXUUMXDNVIRYWSEGFLIAUMLPMHYUTOIKZJMGQKUYHLWBNHJPIDNU
# echo Actual ciphertext:
# ./quagmire encrypt 3 test-encrypt-quagmire-iii-2.txt IGNORE KNOWLEDGE

# echo Expected plaintext: 
# echo WELIVEINASOCIETYEXQUISITELYDEPENDENTONSCIENCEANDTECHNOLOGYINWHICHHARDLYANYONEKNOWSANYTHINGABOUTSCIENCEANDTECHNOLOGYCARLSAGAN
# echo Actual plaintext:
# ./quagmire decrypt 3 test-decrypt-quagmire-iii-2.txt IGNORE KNOWLEDGE

echo
echo -------------------------------------------------------------------------------------------
echo MJ2016-E21 - Quagmire III
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo OHSCIIGCQCGJHPHGCSDBZCVSETHCGJTHTFWMCDDZELQVYKTGRLJENOVTDHPCGSCWTGZVOBQIUCCTNXQBYOUFUKCOWAOXCWGIEEUJFWZCSTPJDEDCRMGQRSUSZPXQIRTRMLGVQROHJXUBYDVUJBDWCDJMGURYLHGWWJMOQKFMDBANNHZLNMZJQFHLENLRJCEOGWGQBWFZKEBYDVNAUSYWETQSDBQYKGO
echo Actual ciphertext:
./quagmire encrypt 3 test-encrypt-quagmire-iii-3.txt PARKINGLOT LABYRINTH

echo Expected plaintext: 
echo AFTERPARKINGMYCARINTHESHOPPINGCENTERICRACKEDTWOWINDOWSFORMYLABWHOWASINTHEBACKSEATASIWALKEDAWAYIPOINTEDATHIMANDREPEATEDSTAYSEVERALTIMESSOHEWOULDNTTRYTOCOMEAFTERMEABLONDELADYINANADJACENTCARSAIDYOUREALLYSHOULDJUSTPUTITINTOPARK
echo Actual plaintext:
./quagmire decrypt 3 test-decrypt-quagmire-iii-3.txt PARKINGLOT LABYRINTH

echo
echo -------------------------------------------------------------------------------------------
echo JA2016-E20 - Quagmire III
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo SMHADAKHSSVQEKTUXFBLNWARQFUFIYNPLFZPNXHUNVUNMVATLYEPJLTYYSCINSTYHFWYESLDDLBRYILFDEIRWFIZSOIWYRLSGYUYFOIISKQYADCHFJYAEATZDFOIYHMKHRGESSDDUDRXBHH
echo Actual ciphertext:
./quagmire encrypt 3 test-encrypt-quagmire-iii-4.txt TRAVEL SECRETS

echo Expected plaintext: 
echo THEREASONJAMESBONDALWAYSPLUMPSFORFLYINGONFRIDAYTHETHIRTEENTHISBECAUSETHEREAREPRACTICALLYNOPASSENGERSANDITSMORECOMFORTABLEANDYOUGETBETTERSERVICE
echo Actual plaintext:
./quagmire decrypt 3 test-decrypt-quagmire-iii-4.txt TRAVEL SECRETS

echo
echo -------------------------------------------------------------------------------------------
echo Example from https://www.cryptogram.org/downloads/aca.info/ciphers/QuagmireIV.pdf
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo VBMRFCYISPMPBRRHEICXRREIGDX
echo Actual ciphertext:
./quagmire encrypt 4 test-encrypt-quagmire-iv.txt SENSORY PERCEPTION EXTRA

echo Expected plaintext: 
echo THISONEEMPLOYSTHREEKEYWORDS
echo Actual plaintext:
./quagmire decrypt 4 test-decrypt-quagmire-iv.txt SENSORY PERCEPTION EXTRA

echo
echo -------------------------------------------------------------------------------------------
echo JA2016-E24 - Quagmire IV
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo AEVSDJBYCLKEMBYFOCGJLZGJBECIWAMKAIPCYLADAYBECXJCSIASYDJAYGEGPACLLYXAYEOVFCZYFFHGCNJZTKXPNXALZYBOKPMLJSSHRLOIHSXEKSKOZYADFLEJRCBAKIELHCMLNAEBFCOUAEBXBLGSVJMETBOKJPQFAGFBRYIHKMIGCZETSOJQBFLNUQHKIJMISHJJWLDMINYLGZTJWKTUFFIIH
echo Actual ciphertext:
./quagmire encrypt 4 test-encrypt-quagmire-iv-3.txt INCUBATORS MEDICAL AMUSEMENT

echo Expected plaintext: 
echo INNINETEENFORTYONEBEFORETHEYWEREACCEPTEDBYTHEMEDICALESTABLISHMENTBABYINCUBATORSWEREANEXHIBITATTHECONEYISLANDAMUSEMENTPARKANDBECAMEITSLONGESTRUNNINGATTRACTIONTHEYWERELOOKEDAFTERBYHIGHLYTRAINEDMEDICALTECHNICIANSANDWETNURSE
echo Actual plaintext:
./quagmire decrypt 4 test-decrypt-quagmire-iv-3.txt INCUBATORS MEDICAL AMUSEMENT

echo
echo -------------------------------------------------------------------------------------------
echo SO2016-E19 - Quagmire IV
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo WTMVBKBCJRHBKTCPQMJYBDXSAJYVQEFLTDLHTDEJTGUBRNJYMHPIVQWMOCZSQTLIYSAQKGWFGQZLEQASZAYAQAIVBUVQEFIJIZUBRNQGUZPRZBNZHPIVXDLIPRLTDLOKILBNZWOTTBPHCQILLPGIYHTILTPTMZJTYISDKQPVCYSAUTFBYRZ
echo Actual ciphertext:
./quagmire encrypt 4 test-encrypt-quagmire-iv-4.txt LAWS OF PHYSICS

echo Expected plaintext: 
echo EINSTEINWROTEANEQUATIONTHATSAYSTHATRIEMANNCURVATUREISEQUIVALENTTOTHEENERGYOFMATTERTHATISTOSAYSPACECURVESWHERETHEREISMATTERTHATISITTHEEQUATIONFITSINTOHALFALINEANDTHEREISNOTHINGMORE
echo Actual plaintext:
./quagmire decrypt 4 test-decrypt-quagmire-iv-4.txt LAWS OF PHYSICS

echo
echo -------------------------------------------------------------------------------------------
echo SO2016-AC1143 - Quagmire IV
echo -------------------------------------------------------------------------------------------
echo Expected ciphertext: 
echo DHJGIYARXYASKFVABIDHIVCOLYDSBODERVZPDNDYARQFLBKYQIJJVNVGDOKSDBJHXIFLJJKCEIRCQWWCYZQZHBDXYQKGINTAWOQPHAEVXAUDQAVYSIDHVAADKYCSLBWCWHUKQWUBXXJZIYTXROTGMHMCFBFQMYTBLPQEUOTVLQFSBNLCLXUDODTEFHREAJQCRIFPUWUBXIRNTYMJNVZPMVMSXXGCQWEBXCN
echo Actual ciphertext:
./quagmire encrypt 4 test-encrypt-quagmire-iv-5.txt PUTTHE RESULTINTO PLACETEN

echo Expected plaintext: 
echo RICHARDRESPONDSTOTHEANGUISHOFHISCONDITIONWITHANOUTCASTSCREDOIAMDETERMINEDTOPROVEAVILLAINANDHATETHEIDLEPLEASURESOFTHESEDAYSANDPLOTSTOHAVEHISBROTHERCLARENCEWHOGOESBEFOREHIMINTHELINEOFTHEIRSUCCESSIONDIRECTEDTOTHETOWEROFLONDONOVERAPROPHECY
echo Actual plaintext:
./quagmire decrypt 4 test-decrypt-quagmire-iv-5.txt PUTTHE RESULTINTO PLACETEN

