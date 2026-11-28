mod form;
mod http;

pub use form::form;
pub use http::{Header, Http, METHODS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum App<'a> {
    Http(Http<'a>),
}

pub fn dissect(payload: &[u8]) -> Option<App<'_>> {
    Http::parse(payload).map(App::Http)
}
