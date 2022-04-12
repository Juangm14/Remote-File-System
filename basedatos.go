package main

import (
	"database/sql"
	"log"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, _ := sql.Open("sqlite3", "user.db?_fk=1")
 
	/*
	sentencia := `create table salt(
		userId INTEGER, 
		salt binary(256),
		FOREIGN KEY (userId) 
		   REFERENCES user (id)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
		PRIMARY KEY (userId,salt)
		 
	);`
*/
	sentencia := `delete  from user `
	statement, err := db.Exec(sentencia)

	if err != nil {
		log.Fatalln(err.Error())
	}
	print(statement)
	defer db.Close()
}
