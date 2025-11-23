use crate::utils::error::Result;
use syn::{Item, ItemFn, ItemImpl, ItemStruct, ItemTrait, ItemEnum, ItemMod};
use quote::ToTokens;

pub struct AstExtractor;

impl AstExtractor {
    pub fn new() -> Self {
        Self
    }
    
    pub fn extract_functions(item: &ItemFn) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        
        let func_info = FunctionInfo {
            name: item.sig.ident.to_string(),
            is_unsafe: item.sig.unsafety.is_some(),
            is_async: item.sig.asyncness.is_some(),
            is_const: item.sig.constness.is_some(),
            generics: Self::extract_generics(&item.sig.generics),
            parameters: Self::extract_parameters(&item.sig.inputs),
            return_type: Self::extract_return_type(&item.sig.output),
            visibility: Self::extract_visibility(&item.vis),
            attributes: Self::extract_attributes(&item.attrs),
            body_complexity: Self::calculate_complexity(&item.block),
            line_count: item.to_token_stream().to_string().lines().count(),
        };
        
        functions.push(func_info);
        functions
    }
    
    pub fn extract_struct_info(item: &ItemStruct) -> StructInfo {
        StructInfo {
            name: item.ident.to_string(),
            visibility: Self::extract_visibility(&item.vis),
            generics: Self::extract_generics(&item.generics),
            fields: Self::extract_fields(&item.fields),
            attributes: Self::extract_attributes(&item.attrs),
            derives: Self::extract_derives(&item.attrs),
            is_union: false,
        }
    }
    
    pub fn extract_impl_info(item: &ItemImpl) -> ImplInfo {
        ImplInfo {
            trait_name: item.trait_.as_ref().map(|(_, path, _)| path.segments.last()
                .map(|seg| seg.ident.to_string())
                .unwrap_or_default()),
            self_type: Self::extract_type_name(&item.self_ty),
            generics: Self::extract_generics(&item.generics),
            methods: Self::extract_impl_methods(item),
            is_unsafe: item.unsafety.is_some(),
        }
    }
    
    pub fn extract_trait_info(item: &ItemTrait) -> TraitInfo {
        TraitInfo {
            name: item.ident.to_string(),
            visibility: Self::extract_visibility(&item.vis),
            generics: Self::extract_generics(&item.generics),
            methods: Self::extract_trait_methods(item),
            supertraits: Self::extract_supertraits(&item.supertraits),
            is_unsafe: item.unsafety.is_some(),
            is_auto: item.auto_token.is_some(),
        }
    }
    
    pub fn extract_enum_info(item: &ItemEnum) -> EnumInfo {
        EnumInfo {
            name: item.ident.to_string(),
            visibility: Self::extract_visibility(&item.vis),
            generics: Self::extract_generics(&item.generics),
            variants: Self::extract_variants(&item.variants),
            attributes: Self::extract_attributes(&item.attrs),
            derives: Self::extract_derives(&item.attrs),
        }
    }
    
    fn extract_generics(generics: &syn::Generics) -> GenericsInfo {
        GenericsInfo {
            type_params: generics.type_params()
                .map(|param| param.ident.to_string())
                .collect(),
            lifetime_params: generics.lifetimes()
                .map(|lifetime| lifetime.lifetime.ident.to_string())
                .collect(),
            const_params: generics.const_params()
                .map(|param| param.ident.to_string())
                .collect(),
            where_clauses: generics.where_clause.as_ref()
                .map(|wc| wc.predicates.to_token_stream().to_string())
                .unwrap_or_default(),
        }
    }
    
    fn extract_parameters(inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>) -> Vec<ParameterInfo> {
        inputs.iter().map(|input| {
            match input {
                syn::FnArg::Receiver(recv) => ParameterInfo {
                    name: "self".to_string(),
                    ty: if recv.mutability.is_some() { "&mut self".to_string() } else { "&self".to_string() },
                    is_mut: recv.mutability.is_some(),
                    is_ref: true,
                },
                syn::FnArg::Typed(pat_type) => {
                    let name = if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                        pat_ident.ident.to_string()
                    } else {
                        "_".to_string()
                    };
                    
                    ParameterInfo {
                        name,
                        ty: pat_type.ty.to_token_stream().to_string(),
                        is_mut: false, // TODO: detect mutability
                        is_ref: false, // TODO: detect reference
                    }
                }
            }
        }).collect()
    }
    
    fn extract_return_type(output: &syn::ReturnType) -> String {
        match output {
            syn::ReturnType::Default => "()".to_string(),
            syn::ReturnType::Type(_, ty) => ty.to_token_stream().to_string(),
        }
    }
    
    fn extract_visibility(vis: &syn::Visibility) -> String {
        match vis {
            syn::Visibility::Public(_) => "pub".to_string(),
            syn::Visibility::Restricted(_) => "pub(restricted)".to_string(),
            syn::Visibility::Inherited => "private".to_string(),
        }
    }
    
    fn extract_attributes(attrs: &[syn::Attribute]) -> Vec<String> {
        attrs.iter()
            .map(|attr| attr.into_token_stream().to_string())
            .collect()
    }
    
    fn extract_derives(attrs: &[syn::Attribute]) -> Vec<String> {
        attrs.iter()
            .filter_map(|attr| {
                if attr.path().is_ident("derive") {
                    Some(attr.into_token_stream().to_string())
                } else {
                    None
                }
            })
            .collect()
    }
    
    fn extract_fields(fields: &syn::Fields) -> Vec<FieldInfo> {
        match fields {
            syn::Fields::Named(named) => {
                named.named.iter().map(|field| FieldInfo {
                    name: field.ident.as_ref().map(|id| id.to_string()).unwrap_or_default(),
                    ty: field.ty.clone().into_token_stream().to_string(),
                    visibility: Self::extract_visibility(&field.vis),
                    attributes: Self::extract_attributes(&field.attrs),
                }).collect()
            }
            syn::Fields::Unnamed(unnamed) => {
                unnamed.unnamed.iter().enumerate().map(|(i, field)| FieldInfo {
                    name: format!("_{}", i),
                    ty: field.ty.clone().into_token_stream().to_string(),
                    visibility: Self::extract_visibility(&field.vis),
                    attributes: Self::extract_attributes(&field.attrs),
                }).collect()
            }
            syn::Fields::Unit => Vec::new(),
        }
    }
    
    fn extract_type_name(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(type_path) => {
                type_path.path.segments.last()
                    .map(|seg| seg.ident.to_string())
                    .unwrap_or_default()
            }
            _ => ty.into_token_stream().to_string(),
        }
    }
    
    fn extract_impl_methods(impl_block: &ItemImpl) -> Vec<MethodInfo> {
        impl_block.items.iter().filter_map(|item| {
            if let syn::ImplItem::Fn(method) = item {
                Some(MethodInfo {
                    name: method.sig.ident.to_string(),
                    is_unsafe: method.sig.unsafety.is_some(),
                    is_async: method.sig.asyncness.is_some(),
                    visibility: Self::extract_visibility(&method.vis),
                    signature: method.sig.clone().into_token_stream().to_string(),
                })
            } else {
                None
            }
        }).collect()
    }
    
    fn extract_trait_methods(trait_item: &ItemTrait) -> Vec<MethodInfo> {
        trait_item.items.iter().filter_map(|item| {
            if let syn::TraitItem::Fn(method) = item {
                Some(MethodInfo {
                    name: method.sig.ident.to_string(),
                    is_unsafe: method.sig.unsafety.is_some(),
                    is_async: method.sig.asyncness.is_some(),
                    visibility: "pub".to_string(), // Trait methods are public by default
                    signature: method.sig.clone().into_token_stream().to_string(),
                })
            } else {
                None
            }
        }).collect()
    }
    
    fn extract_supertraits(supertraits: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>) -> Vec<String> {
        supertraits.iter().map(|bound| {
            match bound {
                syn::TypeParamBound::Trait(trait_bound) => {
                    trait_bound.path.segments.last()
                        .map(|seg| seg.ident.to_string())
                        .unwrap_or_default()
                }
                syn::TypeParamBound::Lifetime(lifetime) => {
                    lifetime.ident.to_string()
                }
                _ => String::new(),
            }
        }).collect()
    }
    
    fn extract_variants(variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>) -> Vec<VariantInfo> {
        variants.iter().map(|variant| VariantInfo {
            name: variant.ident.to_string(),
            fields: Self::extract_fields(&variant.fields),
            discriminant: variant.discriminant.as_ref()
                .map(|(_, expr)| expr.to_token_stream().to_string()),
        }).collect()
    }
    
    fn calculate_complexity(block: &syn::Block) -> usize {
        // Simple complexity calculation based on control flow statements
        let code = block.into_token_stream().to_string();
        let complexity_keywords = ["if", "else", "match", "for", "while", "loop", "?"];
        
        complexity_keywords.iter()
            .map(|keyword| code.matches(keyword).count())
            .sum()
    }
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub is_unsafe: bool,
    pub is_async: bool,
    pub is_const: bool,
    pub generics: GenericsInfo,
    pub parameters: Vec<ParameterInfo>,
    pub return_type: String,
    pub visibility: String,
    pub attributes: Vec<String>,
    pub body_complexity: usize,
    pub line_count: usize,
}

#[derive(Debug, Clone)]
pub struct ParameterInfo {
    pub name: String,
    pub ty: String,
    pub is_mut: bool,
    pub is_ref: bool,
}

#[derive(Debug, Clone)]
pub struct StructInfo {
    pub name: String,
    pub visibility: String,
    pub generics: GenericsInfo,
    pub fields: Vec<FieldInfo>,
    pub attributes: Vec<String>,
    pub derives: Vec<String>,
    pub is_union: bool,
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub ty: String,
    pub visibility: String,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ImplInfo {
    pub trait_name: Option<String>,
    pub self_type: String,
    pub generics: GenericsInfo,
    pub methods: Vec<MethodInfo>,
    pub is_unsafe: bool,
}

#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub name: String,
    pub is_unsafe: bool,
    pub is_async: bool,
    pub visibility: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct TraitInfo {
    pub name: String,
    pub visibility: String,
    pub generics: GenericsInfo,
    pub methods: Vec<MethodInfo>,
    pub supertraits: Vec<String>,
    pub is_unsafe: bool,
    pub is_auto: bool,
}

#[derive(Debug, Clone)]
pub struct EnumInfo {
    pub name: String,
    pub visibility: String,
    pub generics: GenericsInfo,
    pub variants: Vec<VariantInfo>,
    pub attributes: Vec<String>,
    pub derives: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VariantInfo {
    pub name: String,
    pub fields: Vec<FieldInfo>,
    pub discriminant: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GenericsInfo {
    pub type_params: Vec<String>,
    pub lifetime_params: Vec<String>,
    pub const_params: Vec<String>,
    pub where_clauses: String,
}