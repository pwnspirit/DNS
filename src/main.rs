use actix_cors::Cors;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, http::header};
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Deserialize)]
struct LookupRequest {
    domain: String,
}

#[derive(Serialize)]
struct DnsResult {
    record_type: String,
    records: Vec<String>,
}

#[post("/lookup")]
async fn lookup(data: web::Json<LookupRequest>) -> impl Responder {
    let domain = data.domain.clone();
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let mut results = Vec::new();
    let record_types = vec!["A", "AAAA", "MX", "NS", "TXT", "CNAME"];

    for rtype in &record_types {
        let response = match *rtype {
            "A" => resolver.ipv4_lookup(&domain).await.map(|r| r.iter().map(|ip| ip.to_string()).collect()),
            "AAAA" => resolver.ipv6_lookup(&domain).await.map(|r| r.iter().map(|ip| ip.to_string()).collect()),
            "MX" => resolver.mx_lookup(&domain).await.map(|r| r.iter().map(|mx| mx.to_string()).collect()),
            "NS" => resolver.ns_lookup(&domain).await.map(|r| r.iter().map(|ns| ns.to_string()).collect()),
            "TXT" => resolver.txt_lookup(&domain).await.map(|r| {
                r.iter().flat_map(|txt| txt.txt_data().iter().map(|s| String::from_utf8_lossy(s).to_string())).collect()
            }),
            "CNAME" => resolver.lookup(&domain, trust_dns_resolver::proto::rr::RecordType::CNAME).await
                .map(|r| r.iter().map(|rec| rec.to_string()).collect()),
            _ => Err("Unsupported".into()),
        };

        match response {
            Ok(records) => results.push(DnsResult {
                record_type: rtype.to_string(),
                records,
            }),
            Err(e) => results.push(DnsResult {
                record_type: rtype.to_string(),
                records: vec![format!("Error: {}", e)],
            }),
        }
    }

    HttpResponse::Ok().json(results)
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("index.html"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server running on http://0.0.0.0:8080");

    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("https://pwnspirit.github.io/DNS") // 🔁 Replace with your GitHub Pages URL
            .allowed_methods(vec!["POST"])
            .allowed_headers(vec![header::CONTENT_TYPE])
            .max_age(3600);

        App::new()
            .wrap(cors)
            .service(index)
            .service(lookup)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

