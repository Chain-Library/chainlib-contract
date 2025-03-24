#[starknet::contract]
pub mod ChainLib {

    
    use starknet::{ContractAddress};
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess
    };
    
    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
    pub enum ContentType {
        #[default]
        Text,
        Video,
        Image,
        // Any other content type
    }
    
    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Debug)]
    pub enum Category {
        Software,
        #[default]
        Education,
        Literature,
        Art
    }
    
    #[derive(Copy, Drop, Serde, starknet::Store, Debug)]
    pub struct ContentMetadata {
        pub content_id: felt252,
        pub title: felt252,
        pub description: felt252,
        pub content_type: ContentType,
        pub creator: ContractAddress,
        pub category: Category
    }

    #[storage]
    struct Storage {
        owner: ContractAddress,
        creators_content: Map::<ContractAddress, ContentMetadata>,
        content: Map::<felt252, ContentMetadata>,
        content_tags: Map::<ContentMetadata, Array<felt252>>
    }

}