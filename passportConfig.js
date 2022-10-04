const LocalStrategy = require('passport-local').Strategy
const { pool } = require('./dbConfig')
const bcrypt = require('bcrypt')

function initialize(passport) {
    const authenticateUser = (email, password, done) => {
        pool.query(
            `select * from users where email = $1`, [email], (err, results) => {
                if(err) throw err
                console.log(results.rows)
                // Caso user exista
                if(results.rows.length > 0) {
                    // Vai passar o user como objeto
                    const user = results.rows[0]
                    // Agora precisamos comparar a password que o user colocou no input
                    // com a password que está no banco de dados
                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if(err) throw err
                        if(isMatch){
                            // null --> não tem erros & user --> como eh igual retorna o user
                            // ou seja, retorna o user e armazena no cookie
                            return done(null, user)
                        } else {
                            // caso a password não estiver igual ao banco de dados
                            return done(null, false, {message: 'password errada'})
                        }
                    })
                } else {
                    // Se não tiver o user
                    return done(null, false, {message: 'E-mail não registrado'})
                }
            }
        )
    }
    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    }, authenticateUser))

    //Armazenando a id do user na sessão do cookie
    passport.serializeUser((user, done) => done(null, user.id))
    // Retornando o user inteiro a partir da id
    passport.deserializeUser((id, done) => {
        pool.query(
            `select * from users where id = $1`, [id], (err, results) => {
                if(err) throw err
                return done(null, results.rows[0])
            }
        )
    })
}


module.exports = initialize