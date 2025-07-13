use axum::extract::Request;
use axum_casbin::CasbinVals;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct AuthLayer;

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
}

impl<S> Service<Request> for AuthMiddleware<S>
where
    S: Service<Request>,
{
    type Error = S::Error;
    type Future = S::Future;
    type Response = S::Response;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut req: Request) -> Self::Future {
        req.extensions_mut().insert(CasbinVals {
            subject: String::from("alice"),
            domain: None,
        });
        self.inner.call(req)
    }
}

use axum::routing::{Router, get};
use axum_casbin::CasbinAxumLayer;
use axum_casbin::casbin::function_map::key_match2;
use axum_casbin::casbin::{CoreApi, DefaultModel, FileAdapter};

// Handler that immediately returns an empty `200 OK` response.
async fn handler() {}

#[tokio::main]
async fn main() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();

    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinAxumLayer::new(m, a).await.unwrap();

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    let app: Router = Router::new()
        .route("/", get(handler))
        .route("/pen/1", get(handler))
        .route("/pen/2", get(handler))
        .route("/book/{id}", get(handler))
        .layer(casbin_middleware)
        .layer(AuthLayer);
    axum::serve(
        tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .unwrap(),
        app.into_make_service(),
    )
    .await
    .unwrap();
}
