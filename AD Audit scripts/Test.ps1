$a = 'three'
switch ($a) {
 1 {
		'It is one.'
	}
	2 {
		'It is two.'
	}
	{ ($_ -eq 3) -or ($_ -eq 'three') } {
		'It is three.'
	}
	 4 {
		'It is four.'
	}
}
