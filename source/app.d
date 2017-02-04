import std.stdio;
import std.format;

import std.json;

import std.datetime;

string secret = "SuperStrongSecret";

void tester(alias fun)() {
	import core.memory;
	auto s = Clock.currTime;
	for(int i = 0; i < 50000; ++i) {
		fun();
	}

	GC.collect();
	GC.minimize();

	auto ss = Clock.currTime;
	writefln("%s", ss - s);
}

void jwtTest() {
	import jwt.jwt;
	import jwt.algorithms;
	import jwt.exceptions;
	import jwt.algorithms;

	JSONValue user = ["id": JSONValue(1337)];
    Token token = new Token(JWTAlgorithm.HS256);
    token.claims.set("user", user);
    string encodedToken = token.encode(secret);

	long id;

	try {

        Token token2 = verify(encodedToken, secret, [JWTAlgorithm.HS256]);
        JSONValue user2 = token2.claims.getObject("user");

        id = user2["id"].integer();
    } catch (InvalidAlgorithmException e) {
        writeln("token has an invalid algorithm");
    } catch (InvalidSignatureException e) {
        writeln("This token has been tampered with");
    } catch (NotBeforeException e) {
        writeln("Token is not valid yet");
    } catch (ExpiredException e) {
        writeln("Token has expired");
    }

	assert(id == 1337);
}

void fastjwtTest() {
	import fastjwt.jwt;
	import fastjwt.stringbuf;

	auto alg = JWTAlgorithm.HS256;
	StringBuffer buf;
	encodeJWTToken(buf, alg, secret, "id", 1337);

	StringBuffer header;
	StringBuffer payload;

	int rslt = decodeJWTToken(buf.getData(), secret, alg, header, payload);
	assert(rslt == 0, format("%d", rslt));
}

void jwtdTest() {
	import jwtd.jwt;
	auto j = JSONValue(["id" : JSONValue(1337)]);
	string en = encode(j, secret);
	JSONValue v;
   	try {
		v = decode(en, secret);
	} catch(Exception e) {
		writeln(e.toString());
	}

	assert(v["id"].integer() == 1337);
}

void main() {
	tester!fastjwtTest();
	tester!jwtTest();
	tester!jwtdTest();
}
