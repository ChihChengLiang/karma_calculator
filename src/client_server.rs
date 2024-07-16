use rocket::{get, launch, routes};

#[get("/world")]
fn world() -> &'static str {
    "Hello, world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/hello", routes![world])
}

#[cfg(test)]
mod tests {
    use rocket::local::blocking::Client;

    #[test]
    fn hello() {
        let client = Client::tracked(super::rocket()).unwrap();
        let response = client.get("/hello/world").dispatch();
        assert_eq!(response.into_string(), Some("Hello, world!".into()));
    }
}
