#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>

#include "../../../epan/dissectors/packet-tcp.h"
#include "../../../epan/dissectors/packet-xml.h"

#define PCATS_PORT 9000
#define PCATS_HEADER_LENGTH 4

static int proto_pcats = -1;
static dissector_handle_t proto_xml = NULL;

static int hf_pcats_xml_length = -1;
static int hf_pcats_tag = -1;
static gint ett_pcats = -1;
static gint ett_xml = -1;

static int
dissect_pcats_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCATS");

    /* clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* add the length of the xml to the output */
    proto_item *ti = proto_tree_add_item(tree, proto_pcats, tvb, 0, PCATS_HEADER_LENGTH, ENC_NA);
    proto_tree *pcats_tree = proto_item_add_subtree(ti, ett_pcats);
    proto_tree_add_item(pcats_tree, hf_pcats_xml_length, tvb, 0, PCATS_HEADER_LENGTH, ENC_BIG_ENDIAN);

    tvbuff_t *xml_tvb = tvb_new_subset_remaining(tvb, PCATS_HEADER_LENGTH);
    proto_tree* xml_tree = proto_item_add_subtree(ti, ett_xml);
    call_dissector(proto_xml, xml_tvb, pinfo, xml_tree);

    int xml_index= dissector_handle_get_protocol_index(proto_xml);
    xml_frame_t* xml_dissector_frame;
    xml_dissector_frame = (xml_frame_t*)p_get_proto_data(pinfo->pool, pinfo, xml_index, 0);
    if (xml_dissector_frame == NULL)
        return tvb_captured_length(tvb);

    /*data from XML dissector*/
    xml_frame_t* xml_frame;
    xml_frame = xml_dissector_frame->first_child;

    while (xml_frame)
    {
        if (xml_frame->name && strcmp(xml_frame->name, "xml") != 0) {
            proto_tree_add_string(
                pcats_tree, hf_pcats_tag, tvb,
                xml_frame->start_offset, xml_frame->length,
                xml_frame->name);
            col_append_str(pinfo->cinfo, COL_INFO, xml_frame->name);
            break;
        }

        xml_frame = xml_frame->next_sibling;
    }

    return tvb_captured_length(tvb);
}

static int
get_pcats_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
    return (guint)tvb_get_ntohl(tvb, 0) + PCATS_HEADER_LENGTH;
}

static int
dissect_pcats(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    tcp_dissect_pdus(
        tvb, pinfo, tree, TRUE, PCATS_HEADER_LENGTH,
        get_pcats_message_len, dissect_pcats_message, data);
    return tvb_captured_length(tvb);
}

void
proto_register_pcats(void)
{
    static hf_register_info hf[] = {
        { &hf_pcats_xml_length,
            { "PCATS XML Length", "pcats.length",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcats_tag,
            { "PCATS Tag", "pcats.tag",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* register the protocol */
    proto_pcats = proto_register_protocol(
        "PCATS Loyalty Protocol", /* name    */
        "PCATS",                  /* short name */
        "pcats"                   /* filter_name */
    );
    proto_register_field_array(proto_pcats, hf, array_length(hf));

    /* register all protocol subtress */
    static gint* ett[] = {
        &ett_pcats,
        &ett_xml,
    };
    proto_register_subtree_array(ett, array_length(ett));

    /* register the dissector*/
    register_dissector("pcats", dissect_pcats, proto_pcats);
}

void
proto_reg_handoff_pcats(void)
{
    static dissector_handle_t pcats_handle;

    pcats_handle = create_dissector_handle(dissect_pcats, proto_pcats);
    dissector_add_uint("tcp.port", PCATS_PORT, pcats_handle);

    proto_xml = find_dissector_add_dependency("xml", proto_pcats);
}
