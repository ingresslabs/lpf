let () =
  let require condition message = if not condition then failwith message in

  let test_file = Filename.temp_file "lpf-file-util-test" ".tmp" in
  Sys.remove test_file;

  Lpf.File_util.write_file test_file "hello world\n";
  require (Sys.file_exists test_file) "file should exist after write";

  let content = Lpf.File_util.read_file test_file in
  require (content = "hello world\n") "read should match write";

  Lpf.File_util.write_file test_file "overwritten";
  let content = Lpf.File_util.read_file test_file in
  require (content = "overwritten") "overwrite should work";

  Sys.remove test_file;

  let test_dir = Filename.temp_file "lpf-file-util-testdir" "" in
  Sys.remove test_dir;
  Lpf.File_util.ensure_dir ~strict:true test_dir;
  require (Sys.file_exists test_dir && Sys.is_directory test_dir) "ensure_dir should create directory";

  Lpf.File_util.ensure_dir ~strict:true test_dir;
  require (Sys.is_directory test_dir) "ensure_dir on existing directory should be ok";

  let nested = Filename.concat test_dir "subdir" in
  Lpf.File_util.ensure_dir ~strict:true nested;
  require (Sys.file_exists nested && Sys.is_directory nested) "ensure_dir should create nested dirs";

  Sys.rmdir nested;
  Sys.rmdir test_dir;

  let lenient_dir = Filename.temp_file "lpf-file-util-lenient" "" in
  (try Sys.remove lenient_dir with _ -> ());
  let test_file_in_place = lenient_dir ^ ".conflict" in
  (try Sys.remove test_file_in_place with _ -> ());
  Lpf.File_util.write_file test_file_in_place "x";
  (try Lpf.File_util.ensure_dir ~strict:true test_file_in_place; failwith "should have raised" with Failure _ -> ());
  Lpf.File_util.ensure_dir ~strict:false test_file_in_place;
  (try Sys.remove test_file_in_place; Sys.remove lenient_dir with _ -> ());

  Printf.printf "file_util tests passed\n"
