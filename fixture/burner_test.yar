rule burner_domain_0check_shop_97a0a {
	strings:
		$ = "48,99,104,101,99,107,46,115,104,111,112"
		$ = "48, 99, 104, 101, 99, 107, 46, 115, 104, 111, 112"
		$ = "\\x30\\x63\\x68\\x65\\x63\\x6B\\x2E\\x73\\x68\\x6F\\x70"
		$ = "\\x30\\x63\\x68\\x65\\x63\\x6b\\x2e\\x73\\x68\\x6f\\x70"
		$ = "&#48;&#99;&#104;&#101;&#99;&#107;&#46;&#115;&#104;&#111;&#112;"
		$ = "0check.shop" base64
		$ = "0check.shop" fullword
		$ = "pohs.kcehc0" fullword
	condition: any of them
}
