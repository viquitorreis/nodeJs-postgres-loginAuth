const express = require('express')
const app = express()
const { pool } = require('./dbConfig')
const bcrypt = require('bcrypt')
const session = require('express-session')
const flash = require('express-flash')
const passport = require('passport')
const initializePassport = require('./passportConfig')

const PORT = process.env.PORT || 3000

initializePassport(passport)

app.set('view engine', 'ejs')
// Passa os detalhes da form
app.use(express.urlencoded({extended: false}))

app.use(session({
    // Chave q deve ser mantida em segredo que vai encriptar toda informação
    secret: 'secret',
    // Se devemos salvar nossas variaveis de sessão se nada for mudado, que no caso nao queremos
    resave: false,
    // Salva as variaveis para permanecer durante a sessão. Trabalha com o app.use(session)
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(flash())

app.get('/', (req, res) => {
    res.render('index')
})

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register')
})

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login')
})

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.user.name })
})

app.get('/users/logout', (req, res) => {
    req.logOut((err) => {
        if(err) throw err
        res.redirect('/users/login')
    })
    // tem que colocar um container no html. Vou fazer n
    //req.flash('succes_msg', 'Você deslogou')
})

app.post('/users/register', async (req, res) => {
    let { name, email, password, password2} = req.body

    console.log({
        name,
        email,
        password,
        password2
    })
    let errors = []
    if(!name || !email || !password || !password2) {
        errors.push({ message: 'Favor preencher todos os campos.' })
    }
    if(password.length < 6){
        errors.push({ message: 'A password deve ter pelo menos 6 caracteres.' })
    }
    if(password != password2){
        errors.push({ message: 'As passwords devem ser iguais.' })
    }
    if(errors.length > 0){
        res.render('register', { errors })
    } else {
        // Validação de forms passou
        let hashedPassword = await bcrypt.hash(password, 10)
        console.log(hashedPassword)

        pool.query(
            'select * from users where email = $1', [email],
            (err, results) => {
                if(err) throw err
                console.log(results.rows)
                if(results.rows.length > 0){
                    errors.push({ message: 'E-mail já está registrado'})
                    res.render('register', { errors })
                } else {
                    //Não tem o usuario no DB
                    pool.query(
                        `insert into users (name, email, password)
                        values ($1, $2, $3)
                        returning id, password`, [name, email, hashedPassword], (err, results) => {
                            if(err) throw err
                            console.log(results.rows)
                            // flash vai passar uma mensagem na nossa pagiina redirecionada
                            req.flash('succes_msg', 'User registrado. Faça o login')
                            res.redirect('/users/login')
                        }
                    )
                }
            }
        )
    }
})

app.post('/users/login', passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    //mensagem apos redirecionar, mas tem que colocar pra receber no html
    //failureFlash: true
}))

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/users/dashboard')
    }
    next()
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
    res.redirect('/users/login')
}

app.listen(PORT, () => {
    console.log(`Server rodando na porta ${PORT}`)
})

