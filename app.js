import  dontenv  from'dotenv';
import Express  from "express";
import mongoose from 'mongoose';
import bcrypt from 'bcrypt'
import  Jwt  from 'jsonwebtoken';
import User from './models/User.js';

dontenv.config();

const app = Express(); 

// Body Parser 

app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());

// json response
app.use(Express.json())

// rotas public
app.get('/',(req,res)=>{
    res.status(200).json({msg:'Bem vindo a nossa Api!'})

})

// rota privada
app.get("/user/:id",checkToken,async(req,res)=>{
    const id = req.params.id
    // se o usuário existe
    const user = await User.findById(id,'-password')

    if(!user){
        return res.status(404).json({msg:'usuário não encontrado!!'})
    }

    res.status(200).json({user})
})

function checkToken(req,res,next){
const authHeader = req.headers['authorization']
const token = authHeader && authHeader.split(' ')[1]

if(!token){
    return res.status(401).json({msg:'acesso negado!'})
}
try {
    const secret = process.env.SECRET
    Jwt.verify(token,secret)
    next()
} catch (error) {
    console.log(error)
    res.status(400).json({msg:"token inválido"})
}
}

// registre user
   
app.post('/auth/register',async(req,res)=>{
    const { name , email , password , confirmpassword} = req.body
    
    //validations
    if(!name){
        return res.status(422).json({msg:'o nome é obrigatório!'})
    }
    if(!email){
        return res.status(422).json({msg:'o email é obrigatório!'})
    }
    if(!password){
        return res.status(422).json({msg:'a senha é obrigatória!'})
    }

    if(password != confirmpassword){
        return res.status(422).json({msg:'as senhas não conferem!'})

    }

    // verificar se o usuário existe
    const userExists = await User.findOne({email:email})

    if (userExists){
        return res.status(422).json({msg:'por favor, utilize outro email!'})

    }
    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password,salt)

    // create user 
    const user = new User({
        name,
        email,
        password: passwordHash,
    })
 
    try {

        await user.save()
        res.status(201).json({msg:"Usuário cadastrado com sucesso"})
        
    } catch (error) {
        console.log(error)
        res.status(500).json({msg:"Aconteceu um erro no servidor tente novamnete mais tarde!",})
    }
})

// login  user

app.post('/auth/login',async (req,res)=>{
    const {email , password} = req.body;

    if(!email){
        return res.status(422).json({msg:'o email é obrigatório!'})
    }
    if(!password){
        return res.status(422).json({msg:'a senha é obrigatória!'})
    }

    // checar se o usuário existe
    const user = await User.findOne({email:email})

    if (!user){
        return res.status(422).json({msg:'usuário não encontrado!'})
    }

    // checar a senha do usário se ela existe
    const checkPassword = await bcrypt.compare(password,user.password)
    
    if(!checkPassword){
        return res.status(422).json({msg:'senha inválida!'})
    }
    try {
        const secret = process.env.SECRET
        const token = Jwt.sign(
            {id:user._id},
            secret,
            {expiresIn: '8h'}

        ) 
        res.status(200).json({msg:"Atenticação realizada com sucesso",token})
        console.log({token})
      
    } catch (error) {
        console.log(error)
        res.status(500).json({msg:"Aconteceu um erro no servidor tente novamnete mais tarde!",})   
    }
})

// conexão com mongoDB
        // credenciais
const dbUser =  process.env.DB_USER
const dbPassword =  process.env.DB_PASS
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.cekjod9.mongodb.net/?retryWrites=true&w=majority`,{
    useNewUrlParser: true, 
    useUnifiedTopology: true  
})
.then(()=>{
    console.log('conectado ao banco!')  

}).catch((err)=>{
    console.log('erro ao se conectar ao banco '+ err)

})

app.listen(3000)