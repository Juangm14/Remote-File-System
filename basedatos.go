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
	/*sentencia := `create table user(
		id integer primary key autoincrement,
		name text unique not null,
		password text not null
	)`*/
	sentenciaUser := `select name from user where id=?`
	statement, err := db.Prepare(sentenciaUser)
	if err != nil {
		log.Fatalln(err.Error())
	}
	v2 := statement.QueryRow(1)

	var name string
	v2.Scan(&name)
	println(name)
}
