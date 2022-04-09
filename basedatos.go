package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, _ := sql.Open("sqlite3", "user.db")

	sentencia := `CREATE TABLE salt(
		userId INTEGER,
		salt binary(256),
		FOREIGN KEY (userId) 
		   REFERENCES user (id)); `

	statement, _ := db.Exec(sentencia)

	print(statement)
	defer db.Close()
}
