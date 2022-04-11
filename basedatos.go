package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, _ := sql.Open("sqlite3", "user.db")
 /*
	sentencia := `create table user(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name text NOT NULL ,
		password text NOT NULL
	);`
*/
	sentencia := `drop table sqlite_sequence`
	statement, _ := db.Exec(sentencia)

	print(statement)
	defer db.Close()
}
