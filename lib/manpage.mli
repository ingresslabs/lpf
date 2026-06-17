type man_page = {
  filename : string;
  section : int;
  title : string;
  content : string;
}

val man_pages : unit -> man_page list
val man_page_content : man_page -> string
