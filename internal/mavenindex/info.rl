package mavenindex

%% machine info;

func (s *recordState) parseInfo2(data []byte) error{
	cs, p, pe, eof := 0, 0, len(data), len(data)
	mark := 0

	%%{
		action mark      { mark = p }
		action packaging { s.Packaging = string(data[mark:p])}
		action extension { s.FileExenstion = string(data[mark:p])}
		str     = [^|]*;
		ignored = "|" str;
		info    = "NA" any*
		        | (str >mark %packaging) ignored{,5}
		        | (str >mark %packaging) ignored{5} "|" (str >mark %extension) ignored*
		        ;

		main := info;
		write init;
		write exec;
	}%%
	
	if cs < info_first_final {
		if p == pe {
			return fmt.Errorf("unexpected eof: %q", data)
		} else {
			return fmt.Errorf("error in info  at pos %d: %q", p, data)
		}
	}

	if s.Packaging != "" && s.FileExension == "" {
		ext := "jar" // Guess
		if p := s.Packaging; s.Classifier != "" || p == "pom" || p == "war" || p == "ear" {
			ext = p
		}
		s.FileExtension = ext
	}

	return nil
}

%% write data;
