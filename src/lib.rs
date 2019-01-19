
#[macro_use]
extern crate diesel;
extern crate dotenv;
extern crate rocket;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rocket_contrib;
extern crate rocket_cors;
extern crate serde_json;
extern crate uuid;
#[macro_use]
extern crate log;
extern crate bcrypt;
extern crate chrono;

use std::net::IpAddr;
use diesel::query_builder::{SelectStatement};
use diesel::expression::bound::Bound;
use diesel::sql_types::Text;

use diesel::query_dsl::filter_dsl::FilterDsl;
use std::marker::PhantomData;
use chrono::offset::Local;
use chrono::{Duration, DateTime};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use dotenv::dotenv;
use rocket::http::{Status, ContentType};
use rocket::request::{self, FromRequest};
use rocket::Rocket;
use rocket::{Outcome, Request, State};
use rocket::http::Header;
use rocket::local::{Client};
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors};
use std::env;
use std::ops::Deref;
use bcrypt::{hash, verify, BcryptError};
use rocket::http::Method;
use rocket::response::Responder;
use rocket::Response;
use uuid::Uuid;

use diesel::{QueryDsl, ExpressionMethods};

/*
use rocket::http::hyper::header::{Authorization, Basic, Bearer, Headers};
use rocket_contrib::Json;
use rocket::response::status;
use rocket::response::status::BadRequest;
use rocket::response::content::Html;
use rocket::response::Redirect;
use rocket::request::Form;
rocket::http::Cookies;
*/

// MYSQL CONNECTION
pub type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;
pub struct DbConn(pub PooledConnection<ConnectionManager<MysqlConnection>>);

impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let pool = request.guard::<State<MysqlPool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(DbConn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ())),
        }
    }
}

impl Deref for DbConn {
    type Target = MysqlConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn create_conn() -> MysqlPool {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set!");
    let manager = ConnectionManager::<MysqlConnection>::new(db_url);
    Pool::new(manager).expect("Failed to create database pool.")
}
//-----------------------------


//-----------------------------
// Error Handling

//200 OK
//201 Created
//204 No content (delete query for example, no return value except "it worked")
//304 Not Modified (client should have the data in cache)
//400 Bad Request
//401 Unauthorized (missing credentials)
//403 Forbidden (credentials valid, but access denied/permissions)

#[derive(Debug, Clone, PartialEq)]
pub struct ReturnStatus {
    pub status: Status,
    pub message: Option<String>,
}

impl ReturnStatus {
    pub fn new(status: Status) -> Self {
        ReturnStatus {
            status,
            message: None,
        }
    }
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
}

impl<'r> Responder<'r> for ReturnStatus {
    fn respond_to(self, req: &Request) -> Result<Response<'r>, Status> {
        let mut build = Response::build();
        if let Some(responder) = self.message {
            build.merge(responder.respond_to(req)?);
        }

        build.status(self.status).ok()
    }
}

//----------------------


//----------------------
//Login guard

/// Ensures that the user is logged in and that the request includes a X-Authorization: Bearer token
/// # Test
/// curl -H "X-Authorization:  Bearer maboi" raidable.ddns.net:27015/user
///
/// # Generic Parameters
/// R: Resulting User type
/// UT: User table type
/// T: Token diesel type
pub struct UserLogged {
    pub token: String,
    //phantom_data: PhantomData<(UT, T)>,
}

//impl<'a, 'r, R: Sized, UT: FilterDsl<SelectStatement<UT, DefaultSelectClause, NoDistinctClause, WhereClause<diesel::expression::operators::Eq<T, Bound<Text, &String>>>>>+Sized, T: ExpressionMethods+Sized> FromRequest<'a, 'r> for UserLogged<R, UT, T> {
impl<'a, 'r/*, R, UT: Table, T: ExpressionMethods*/> FromRequest<'a, 'r> for UserLogged {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<UserLogged, Self::Error> {
        let db = DbConn::from_request(request);
        if let Outcome::Failure(e) = db {
            return Outcome::Failure(e);
        }

        // token from request header
        let token = request.headers().get_one("X-Authorization");
        if let Some(token) = token {
            let token = token.trim();
            if !token.starts_with("Bearer ") {
                return Outcome::Failure((Status::BadRequest, ()));
            }
            let token = &token[7..]; // Possible DOS, mitigated by trim()
                                     // user from token db
            //let user = user_from_token(token, db.as_ref().unwrap());
            let user = Uuid::parse_str(token);

            // Get user from token
            //let user = UT::filter(T::eq(token)).first::<R>(db.as_ref().unwrap());
            if let Ok(u) = user {
                //Outcome::Success(UserLogged { user: u,  phantom_data: PhantomData})
                Outcome::Success(UserLogged { token: u.to_string(),})
            } else {
                Outcome::Failure((Status::Unauthorized, ()))
            }
        } else {
            Outcome::Failure((Status::Unauthorized, ()))
        }
    }
}



pub struct UserIp(Option<IpAddr>);

impl<'a, 'r> FromRequest<'a, 'r> for UserIp {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(UserIp(request.client_ip()))
    }
}

/*
fn foo<UT, T, R, K>(db: &PgConnection, token: K, table: UT) -> Result<R, diesel::result::Error> where
    UT: Table + QueryDsl + FilterDsl<Eq<T, K>>,
    T: Column + ExpressionMethods + Default,
    K: AsExpression<T::SqlType>,
    Filter<UT, Eq<T, K>>: QueryDsl +  LimitDsl + RunQueryDsl<PgConnection>,
    Limit<Filter<UT, Eq<T, K>>>: LoadQuery<PgConnection, R>
{

    <UT as FilterDsl<_>>::filter(table, T::default().eq(token)).first::<R>(db)
}
*/

//----------------------


pub fn do_login(db_pass: &String, input_pass: &String) -> Option<Uuid> {
    match verify(&input_pass, &db_pass) {
        Ok(true) => {
            let token = Uuid::new_v4();
            Some(token)
        }
        _ => None
    }
}

pub fn hash_password(pass: &str) -> Result<String,BcryptError> {
	hash(pass, bcrypt::DEFAULT_COST)
}


pub fn instant_in_days(days: i64) -> DateTime<Local> {
	Local::now() + Duration::days(days)
}


pub fn rocket_trajectory_restriction(restrict_origin: Option<&[&str]>) -> Cors {
    //let (allowed_origins, failed_origins) = AllowedOrigins::some(&["http://raidable.ddns.net"]);
    let allowed = if let Some(origins) = restrict_origin {
    	AllowedOrigins::some(origins).0
    } else {
    	AllowedOrigins::all()
    };
    rocket_cors::Cors {
        allowed_origins: allowed,
        allowed_methods: vec![Method::Get, Method::Post]
            .into_iter()
            .map(From::from)
            .collect(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
}


/*pub fn make_rocket() -> Rocket {
    let options = rocket_trajectory_restriction(None);
    rocket::ignite()
        .manage(create_conn())
        .mount(
            "/",
            routes![
                login,
                register,
                change_password,
                logout,
                get_community_all,
                get_user_all,
            ],
        )
        .attach(options)
}*/





//-----------------------------------------
// Stuff meant for testing from here on
pub fn rocket_client(rocket_instance: Rocket) -> Client {
    Client::new(rocket_instance).expect("Invalid rocket instance")
}

pub fn json_post_ok(rocket_instance: Rocket, target: &str, data: &str) {
    let client = rocket_client(rocket_instance);
    let response = client
        .post(target)
        .header(ContentType::JSON)
        .body(data)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
}
pub fn json_post_status(rocket_instance: Rocket, target: &str, data: &str, status: Status) {
    let client = rocket_client(rocket_instance);
    let response = client
        .post(target)
        .header(ContentType::JSON)
        .body(data)
        .dispatch();
    assert_eq!(response.status(), status);
}
pub fn get_ok(rocket_instance: Rocket, target: &str) {
    let client = rocket_client(rocket_instance);
    let response = client.get(target).dispatch();
    assert_eq!(response.status(), Status::Ok);
}
pub fn get_auth_ok(rocket_instance: Rocket, target: &str, token: &str) {
    get_auth_status(rocket_instance, target, token, Status::Ok);
}
pub fn get_auth_status(rocket_instance: Rocket, target: &str, token: &str, status: Status) {
    let client = rocket_client(rocket_instance);
    let response = client
        .get(target)
        .header(Header::new("X-Authorization", format!("Bearer {}", token)))
        .dispatch();
    assert_eq!(response.status(), status);
}
