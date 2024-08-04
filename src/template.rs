pub use load::load_template;
pub use render::render_template;
mod load {
    pub struct TemplateLoader {
        pub template: String,
    }
    
    pub async fn load_template() -> TemplateLoader {
        let s = String::from("Hello, world!");
        TemplateLoader {
            template: s
        }
    }
}

mod render {
    use crate::template::load::TemplateLoader;

    pub async fn render_template(template: &TemplateLoader) -> String {
        template.template.to_string()
    }
}