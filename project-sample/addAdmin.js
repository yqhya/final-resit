const sqlite= require('sqlite3')
const db= new sqlite.Database('travel.db')
db.run(`INSERT INTO USER (name,email,password,isadmin) VALUES ('admin','admin','admin',1)`,(err)=>{
    if(err)
        console.log(err.message)
    else
    console.log('admin added')
})