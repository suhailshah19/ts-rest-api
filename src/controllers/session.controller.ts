import { Request, Response } from 'express'
import config from 'config'
import { createSession } from '../service/session.service';
import { validatePassword } from '../service/user.service'
import { signJwt } from '../utils/jwt.utils';

export async function createUserSessionHandler(req: Request, res: Response) {
    
    // valuidate the users password
    const user = await validatePassword(req.body)

    if (!user) {
        return res.status(401).send("Invalid email or password");
    }

    // create session
    const session = await createSession(user._id, req.get("user-agent") || "");

    // create an access token
    const accessToken = signJwt(
        { ...user, session: session._id },
        { expiresIn: config.get("accessTokenTtl") } // 15 minutes
    );

    // create a refresh token
    const refreshToken = signJwt(
        { ...user, session: session._id },
        { expiresIn: config.get("accessTokenTtl") }
    );

    // return access & refresh token
    return res.send({ accessToken, refreshToken });
}