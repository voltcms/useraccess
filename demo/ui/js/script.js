document.addEventListener('DOMContentLoaded', function () {
    loadUsers();
    loadGroups();
    // loadGroupMembers();
    document.getElementById("createUserForm").addEventListener("submit", (event) => {
        event.preventDefault();
        createUser();
    });
    document.getElementById("createGroupForm").addEventListener("submit", (event) => {
        event.preventDefault();
        createGroup();
    });
    document.getElementById("deleteUserForm").addEventListener("submit", (event) => {
        event.preventDefault();
        deleteUser(document.getElementById("deleteUserModal").dataset.id, function(){
            bootstrap.Modal.getInstance(document.getElementById("deleteUserModal")).hide();
            loadUsers();
        });
    });
    document.getElementById("deleteGroupForm").addEventListener("submit", (event) => {
        event.preventDefault();
        deleteGroup(document.getElementById("deleteGroupModal").dataset.id, function(){
            bootstrap.Modal.getInstance(document.getElementById("deleteGroupModal")).hide();
            loadGroups();
        });
    });
    document.getElementById('createGroupModal').addEventListener('show.bs.modal', event => {
        loadGroupMembers();
    });
});

async function loadUsers() {
    fetch("../api/scim/users")
        .then(response => response.json())
        .then(data => {
            if (!data || !data.Resources || data.Resources.length == 0) {
                return;
            }
            if (window.userTable) {
                window.userTable.destroy();
            }
            window.userTable = new simpleDatatables.DataTable("#users", {
                data: {
                    headings: [
                        'ID',
                        'User Name',
                        'Display Name',
                        // 'Family Name',
                        // 'Given Name',
                        'Email',
                        'Active',
                        'Action'
                        // 'meta', 
                        // 'schemas', 
                        // 'urn', 
                        // 'userType'
                    ],
                    data: data.Resources.map((item) => {
                        return [
                            item.id,
                            item.userName,
                            item.displayName,
                            // item.name.familyName,
                            // item.name.givenName,
                            item.emails[0].value,
                            item.active,
                            ""
                            // item.meta.location,
                            // item.schemas,
                            // item.urn,
                            // item.userType,
                            // item.locale,
                            // item.phoneNumbers,
                            // item.groups
                        ];
                    })
                },
                columns: [
                    {
                        select: 0,
                        hidden: true
                    },
                    {
                        select: 1,
                        sort: "asc"
                    },
                    {
                        select: 4,
                        type: "boolean"
                    },
                    {
                        select: 5,
                        sortable: false,
                        render: function (data, cell, dataIndex, _cellIndex) {
                            return '<button class="btn btn-success btn-sm me-1 btn-update-user">Update</button><button class="btn btn-danger btn-sm btn-delete-user">Delete</button>';
                        }
                    }
                ]
            });
            window.userTable.on("datatable.init", () => {
                document.querySelectorAll(".btn-update-user").forEach((element) => {
                    element.addEventListener("click", (e) => {
                        const modal = document.getElementById('updateUserModal');
                        modal.addEventListener('show.bs.modal', event => {
                            const index = e.target.parentElement.parentElement.dataset.index;
                            modal.dataset.id = window.userTable.data.data[index].cells[0].data[0].data;
                            modal.dataset.name = window.userTable.data.data[index].cells[1].data[0].data;
                            document.getElementById('updateUserModalTitleName').textContent = modal.dataset.name;
                        });
                        new bootstrap.Modal(modal).show();
                    });
                });
                document.querySelectorAll(".btn-delete-user").forEach((element) => {
                    element.addEventListener("click", (e) => {
                        const modal = document.getElementById('deleteUserModal');
                        modal.addEventListener('show.bs.modal', event => {
                            const index = e.target.parentElement.parentElement.dataset.index;
                            modal.dataset.id = window.userTable.data.data[index].cells[0].data[0].data;
                            modal.dataset.name = window.userTable.data.data[index].cells[1].data[0].data;
                            document.getElementById('deleteUserModalTitleName').textContent = modal.dataset.name;
                            document.getElementById('deleteUserModalBodyName').textContent = modal.dataset.name;
                        });
                        new bootstrap.Modal(modal).show();
                    });
                });
            });
        })
}

async function loadGroups() {
    fetch("../api/scim/groups")
        .then(response => response.json())
        .then(data => {
            if (!data || !data.Resources || data.Resources.length == 0) {
                return;
            }
            if (window.groupTable) {
                window.groupTable.destroy();
            }
            window.groupTable = new simpleDatatables.DataTable("#groups", {
                data: {
                    headings: [
                        'ID',
                        'Display Name',
                        'Action'
                    ],
                    data: data.Resources.map((item) => {
                        return [
                            item.id,
                            item.displayName,
                            ""
                        ];
                    })
                },
                columns: [
                    {
                        select: 0,
                        hidden: true
                    },
                    {
                        select: 1,
                        sort: "asc"
                    },
                    {
                        select: 2,
                        sortable: false,
                        render: function (data, cell, dataIndex, _cellIndex) {
                            return '<button class="btn btn-success btn-sm me-1 btn-update-group">Update</button><button class="btn btn-danger btn-sm btn-delete-group">Delete</button>';
                        }
                    }
                ]
            });
            window.groupTable.on("datatable.init", () => {
                document.querySelectorAll(".btn-update-group").forEach((element) => {
                    element.addEventListener("click", (e) => {
                        const modal = document.getElementById('updateGroupModal');
                        modal.addEventListener('show.bs.modal', event => {
                            const index = e.target.parentElement.parentElement.dataset.index;
                            modal.dataset.id = window.groupTable.data.data[index].cells[0].data[0].data;
                            modal.dataset.name = window.groupTable.data.data[index].cells[1].data[0].data;
                            document.getElementById('updateGroupModalTitleName').textContent = modal.dataset.name;
                        });
                        new bootstrap.Modal(modal).show();
                    });
                });
                document.querySelectorAll(".btn-delete-group").forEach((element) => {
                    element.addEventListener("click", (e) => {
                        const modal = document.getElementById('deleteGroupModal');
                        modal.addEventListener('show.bs.modal', event => {
                            const index = e.target.parentElement.parentElement.dataset.index;
                            modal.dataset.id = window.groupTable.data.data[index].cells[0].data[0].data;
                            modal.dataset.name = window.groupTable.data.data[index].cells[1].data[0].data;
                            document.getElementById('deleteGroupModalTitleName').textContent = modal.dataset.name;
                            document.getElementById('deleteGroupModalBodyName').textContent = modal.dataset.name;
                        });
                        new bootstrap.Modal(modal).show();
                    });
                });
            });
        })
}

async function loadGroupMembers() {
    fetch("../api/scim/users")
        .then(response => response.json())
        .then(data => {
            if (!data || !data.Resources || data.Resources.length == 0) {
                return;
            }
            if (window.groupMemberTable) {
                window.groupMemberTable.destroy();
            }
            window.groupMemberTable = new simpleDatatables.DataTable("#groupMembers", {
                data: {
                    headings: [
                        'ID',
                        'User Name',
                        'Display Name',
                        'Action'
                    ],
                    data: data.Resources.map((item) => {
                        return [
                            item.id,
                            item.userName,
                            item.displayName,
                            false
                        ];
                    })
                },
                columns: [
                    {
                        select: 0,
                        hidden: true
                    },
                    {
                        select: 1,
                        sort: "asc"
                    },
                    {
                        select: 3,
                        sortable: false,
                        type: "boolean",
                        render: function (data, cell, dataIndex, _cellIndex) {
                            if (data) {
                                return '<button type="button" class="btn btn-danger btn-remove-group-member">Remove</button>';
                            } else {
                                return '<button type="button" class="btn btn-success btn-add-group-member">Add</button>';
                            }
                        }
                    }
                ]
            });
            window.groupMemberTable.dom.addEventListener("click", event => {
                if (event.target.matches(".btn-remove-group-member") || event.target.matches(".btn-add-group-member")) {
                    event.preventDefault();
                    event.stopPropagation();
                    const index = parseInt(event.target.parentElement.parentElement.dataset.index, 10);
                    window.groupMemberTable.data.data[index].cells[3].data = event.target.matches(".btn-add-group-member") ? true : false;
                    window.groupMemberTable.update();
                }
            });
        });
}

async function createUser() {
    const formData = new FormData(document.getElementById("createUserForm"));
    var data =
    {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User"
        ],
        "userName": formData.get("userName"),
        "password": formData.get("password"),
        "displayName": formData.get("givenName") + " " + formData.get("familyName"),
        "active": formData.get("active") == 'on' ? true : false,
        "name": {
            "familyName": formData.get("familyName"),
            "givenName": formData.get("givenName")
        },
        "emails": [
            {
                "type": "work",
                "primary": "true",
                "value": formData.get("email")
            }
        ]
    };
    var data = JSON.stringify(data);
    fetch("../api/scim/users", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: data
    }).then(response => response.json()
    ).then(data => {
        if (data.schemas && data.schemas.length > 0 && data.schemas[0] && data.schemas[0] == "urn:ietf:params:scim:schemas:core:2.0:User") {
            bootstrap.Modal.getInstance(document.getElementById("createUserModal")).hide();
            loadUsers();
        }
    }
    );
}

async function createGroup() {
    const formData = new FormData(document.getElementById("createGroupForm"));
    var data =
    {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        ],
        "displayName": formData.get("displayName")
    };
    data["members"] = [];
    window.groupMemberTable.data.data.forEach((item) => {
        if (item.cells[3].data) {
            data["members"].push({
                "value": item.cells[0].data[0].data
            });
        }
    });
    var data = JSON.stringify(data);
    fetch("../api/scim/groups", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: data
    }).then(response => response.json()
    ).then(data => {
        if (data.schemas && data.schemas.length > 0 && data.schemas[0] && data.schemas[0] == "urn:ietf:params:scim:schemas:core:2.0:Group") {
            bootstrap.Modal.getInstance(document.getElementById("createGroupModal")).hide();
            loadGroups();
        }
    }
    );
}

async function deleteUser(id, onSuccess) {
    fetch("../api/scim/users/" + id, {
        method: 'DELETE',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    }).then().then(data => {
        if (data.status == 204) {
            onSuccess();
        }
    }
    );
}

async function deleteGroup(id, onSuccess) {
    fetch("../api/scim/groups/" + id, {
        method: 'DELETE',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    }).then().then(data => {
        if (data.status == 204) {
            onSuccess();
        }
    }
    );
}