use karma_calculator::rocket as rocket_main;
use rocket;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket_main().launch().await?;
    Ok(())
}
