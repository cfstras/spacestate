extern crate prost_build;

fn main() {
    const SERIALIZE: &str = "#[derive(Serialize)]";

    prost_build::Config::default()
        .type_attribute(".MumbleProto.Version", SERIALIZE)
        .type_attribute(".MumbleProto.ChannelState", SERIALIZE)
        .type_attribute(".MumbleProto.UserState", SERIALIZE)
        .type_attribute(".MumbleProto.SuggestConfig", SERIALIZE)
        .type_attribute(".MumbleProto.ServerSync", SERIALIZE)
        .type_attribute(".MumbleProto.ServerConfig", SERIALIZE)
        .compile_protos(&["src/mumble.proto"], &["src/"])
        .unwrap();
}
