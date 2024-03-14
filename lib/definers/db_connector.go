package definers

import (
  "fmt"
  "database/sql"
  _"github.com/go-sql-driver/mysql"
)

// Initialize database connection for the given domain
type DBConfig struct {
  Username string
  Password string
  DBName string
  Host string
}

/*
  NewMySQLConnector() and IntitializeConnector() are seperated to allow
  one to create multiple connectors/connections and handle them
  as per need, However mysql has a connection pool functionality
  we might revert to that
*/

// Initiate a new MysqlDB COnnector
func NewMySQLConnector(db_config *DBConfig) (*sql.DB,error) {
  db,err := sql.Open("mysql",fmt.Sprintf("%s:%s@tcp(%s)/%s",db_config.Username,db_config.Password,db_config.Host,db_config.DBName))
  if err != nil{
    return nil,fmt.Errorf("Error creating new Connector: %v",err)
  }
  return db,nil
}

// Initialize a db configurator
func IntitializeConnector(username,pass,host,dbname string)*DBConfig{
  return &DBConfig{
    Username:username,
    Password: pass,
    DBName: dbname,
    Host: host,
  }
}
