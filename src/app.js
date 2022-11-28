import express, { response } from "express"
import users from "./database"
import { v4 as uuidv4 } from "uuid"
import { compare, hash } from "bcryptjs"
import jwt from "jsonwebtoken"
import 'dotenv/config'

const app = express()

app.use(express.json())

const port = 3000

const ensureAuthMiddleware = (req, res, next) => {
    let authorization = req.headers.authorization

    if(!authorization) {
        return res.status(401).json({
            message: "Missing authorization headers"
        })
    }

    authorization = authorization.split(" ")[1]

    jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
        if(error){
            return res.status(401).json({
                message: "Missing authorization headers"
            })
        }

        const values = {
            uuid: decoded.sub,
            isAdm: decoded.isAdm
        }
        req.user = values
    })
    return next()
}

const ensureAuthMiddlewareEdit = (req, res, next) => {
    let authorization = req.headers.authorization

    if(!authorization) {
        return res.status(401).json({
            message: "Missing authorization headers"
        })
    }

    const token = authorization.split(" ")[1]

    jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
        if(error){
            return res.status(401).json({
                message: "Missing authorization headers"
            })
        }

        const foundUser = decoded.sub

        const userIndex = users.findIndex((el) => el.uuid === foundUser)

        if(userIndex === -1){
            return res.status(403).json({
                message: "User not found"
            })
        }

        req.userIndex = userIndex

    })
    return next()
    
}

const ensureIsAdm = (req, res, next) => {

    const {isAdm} = req.user

    if(!isAdm) {
        return res.status(403).send({
            message: "missing admin permissions"
        })
    }

    return next()
}


const ensureAdmToken = (req, res, next) => {
    const user = users[req.userIndex]

    if(!user.isAdm && req.params.uuid !== user.uuid) {
        return res.status(403).json({
            message: "missing admin permissions"
        })
        
    }
    return next()
}

const serviceCreateUser = async ({name, email, password, isAdm}) => {

    password =  await hash(password, 10)

    const user = {
        uuid: uuidv4(),
        name,
        email,
        password,
        isAdm,
        createdOn: new Date(),
        updatedOn: new Date()
    }

    const userToShow = {
        uuid: uuidv4(),
        name,
        email,
        isAdm,
        createdOn: new Date(),
        updatedOn: new Date()
    }

    const alreadyExists = users.find(user => user.email === email) 

    if(alreadyExists) {
        return [ 409, {message : "E-mail already registered."}]
    } else {
        users.push(user)
        return [ 201, userToShow ]
    }

}

const serviceListUsers = async () => {
    return users
}

const createSessionService = async ({email, password}) => {
    const user = users.find(el => el.email === email)

    if(!user) {
        return [ 401, {
            message: "Wrong email/password"
        }]
    }

    const passwordMatch = await compare(password, user.password)

    if(!passwordMatch){
        return [ 401, {
            message: "Wrong email/password"
        }]
    }

    const token = jwt.sign(
        {
            isAdm: user.isAdm,
        },
        process.env.SECRET_KEY,
        {
            expiresIn: "24h",
            subject: user.uuid
        }
    )

    return [ 200, {token}]

}

const serviceUser = async (uuid) => {
    const user = users.find(el => el.uuid === uuid)
    if(user === -1) {
        return res.status(401).json({
            message: "User not found!"
        })
    }

    delete user.password

    return [200, user]
}

const serviceEditUser = async (id, {name, email, password}) => {

    const findUser = users.find((el) => el.uuid === id)
    
    const findUserIndex = users.findIndex((el) => el.uuid === id)

    const user = {
        uuid: uuidv4(),
        name: name ? name : findUser?.name,
        email: email ? email : findUser?.email,
        updatedOn: new Date(),
        isAdm: findUser?.isAdm,
        createdOn: findUser?.createdOn,
        password: password ? await hash(password, 10) : findUser?.password
    }

    users[findUserIndex] = {...user}

    return [ 200, users[findUserIndex]]
}

const serviceDeleteUser = (index) => {
    users.splice(index, 1)

    return [204, {}]
}


const controllerCreateUser = async (req, res) => {
    const [ status, data ] = await serviceCreateUser(req.body)
    return res.status(status).json(data)
}

const controllerListUsers = async (req, res) => {
    const userData = await serviceListUsers(req.query)
    return res.json(userData)
}

const createSessionController = async (req, res) => {
    const [ status, data ] = await createSessionService(req.body)
    return res.status(status).json(data)
}

const retrieveUserController =  async (req, res) => {
    const [status, data] = await serviceUser(req.user.uuid)
    return res.status(status).json(data)
}

const controllerEditUser = async (req, res) => {
    const [ status, data ] = await serviceEditUser(req.params.uuid, req.body )
    const updatedUser = {
        uuid: data.uuid,
        name: data.name,
        email: data.email,
        isAdm: data.isAdm,
        createdOn: data.createdOn,
        updatedOn: data.updatedOn
    }
    return res.status(status).json(updatedUser)
}

const controllerDeleteUser = async (req, res) => {
    const [ status, data ] = serviceDeleteUser(req.userIndex)
    return res.status(status).json(data)
}


app.post("/users", controllerCreateUser)
app.get("/users", ensureAuthMiddleware, ensureIsAdm, controllerListUsers)
app.get("/users/profile", ensureAuthMiddleware, retrieveUserController)
app.post("/login", createSessionController)
app.patch("/users/:uuid", ensureAuthMiddlewareEdit, ensureAdmToken, controllerEditUser)
app.delete("/users/:uuid", ensureAuthMiddleware, ensureIsAdm, controllerDeleteUser)
app.listen(port, () => console.log(`App rodando na porta ${port}`))

export default app