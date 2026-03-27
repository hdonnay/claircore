package mavenindex


%% machine index;
%% write data;

type lexer2 struct{
	stack []int
	top int
	act int
	ts int
	te int

	fields int
}

%%{
	access l.;

	action store_int {
		intv = int(be.Uint32(data[p-4:p]));
	}
	action store_short {
		intv = int(be.Uint16(data[p-2:p]));
	}
	action string_start {
		strp = p;
		fexec (p + intv);
	}
	action string_eof {
		panic("unexepected eof:", p, pe, eof, intv, strp)
	}
	action store_string {
		str = data[strp:p];
		strp = -1;
	}
	action store_fields {
		l.fields = intv;
	}
	action test_fields { l.testFields() }

	int := any{4} %store_int;
	short := any{2} %store_short;
	string := any* >string_start @/string_eof %store_string;

	field := any short string %store_key (
		skip_value when test_skip_value
		|
		store_value when test_store_value
	);

	record := int %store_fields ( field when test_fields )*
	main := todo;
}%%

func (l *lexer2) init() {
%% write init;
}

func (l *lexer2) testFields() (ok bool) {
	ok = l.fields > 0
	l.fields--
	return ok
}


func (l *lexer2) run(data []byte) (int, error){
	cs, p, pe, eof := 0, 0, len(data), len(data)
	intv, strp := -1, -1
	var str []byte
	fieldCt := 0

%% write exec;

	return 0, nil
}
