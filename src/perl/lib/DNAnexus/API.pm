# Do not modify this file by hand.
#
# It is automatically generated by src/api_wrappers/generatePerlAPIWrappers.py.
# (Run make api_wrappers to update it.)

package DNAnexus::API;

use strict;
use Exporter;
use DNAnexus qw(DXHTTPRequest);


sub appAddCategories($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/addCategories', $input_params, %kwargs);
}

sub appAddCategoriesWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appAddCategories($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appAddDevelopers($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/addDevelopers', $input_params, %kwargs);
}

sub appAddDevelopersWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appAddDevelopers($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appAddTags($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/addTags', $input_params, %kwargs);
}

sub appAddTagsWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appAddTags($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appDelete($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/delete', $input_params, %kwargs);
}

sub appDeleteWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appDelete($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appDescribe($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/describe', $input_params, %kwargs);
}

sub appDescribeWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appDescribe($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appGet($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/get', $input_params, %kwargs);
}

sub appGetWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appGet($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appInstall($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/install', $input_params, %kwargs);
}

sub appInstallWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appInstall($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appListCategories($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/listCategories', $input_params, %kwargs);
}

sub appListCategoriesWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appListCategories($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appListDevelopers($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/listDevelopers', $input_params, %kwargs);
}

sub appListDevelopersWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appListDevelopers($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appPublish($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/publish', $input_params, %kwargs);
}

sub appPublishWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appPublish($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appRemoveCategories($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/removeCategories', $input_params, %kwargs);
}

sub appRemoveCategoriesWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appRemoveCategories($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appRemoveDevelopers($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/removeDevelopers', $input_params, %kwargs);
}

sub appRemoveDevelopersWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appRemoveDevelopers($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appRemoveTags($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/removeTags', $input_params, %kwargs);
}

sub appRemoveTagsWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appRemoveTags($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appRun($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/run', $input_params, %kwargs);
}

sub appRunWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appRun($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appUninstall($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/uninstall', $input_params, %kwargs);
}

sub appUninstallWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appUninstall($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appUpdate($;$%) {
    my ($app_id_or_name, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$app_id_or_name.'/update', $input_params, %kwargs);
}

sub appUpdateWithAlias($;$%) {
    my ($app_name, $app_alias, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return appUpdate($app_name.'/'.$app_alias, $input_params, %kwargs);
}


sub appNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/app/new', $input_params, %kwargs);
}


sub appletAddTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTags', $input_params, %kwargs);
}


sub appletAddTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTypes', $input_params, %kwargs);
}


sub appletClose($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/close', $input_params, %kwargs);
}


sub appletDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub appletGet($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/get', $input_params, %kwargs);
}


sub appletGetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/getDetails', $input_params, %kwargs);
}


sub appletListProjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listProjects', $input_params, %kwargs);
}


sub appletRemoveTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTags', $input_params, %kwargs);
}


sub appletRemoveTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTypes', $input_params, %kwargs);
}


sub appletRename($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/rename', $input_params, %kwargs);
}


sub appletRun($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/run', $input_params, %kwargs);
}


sub appletSetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setDetails', $input_params, %kwargs);
}


sub appletSetProperties($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setProperties', $input_params, %kwargs);
}


sub appletSetVisibility($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setVisibility', $input_params, %kwargs);
}


sub appletNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/applet/new', $input_params, %kwargs);
}


sub containerClone($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/clone', $input_params, %kwargs);
}


sub containerDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub containerDestroy($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/destroy', $input_params, %kwargs);
}


sub containerListFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listFolder', $input_params, %kwargs);
}


sub containerMove($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/move', $input_params, %kwargs);
}


sub containerNewFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/newFolder', $input_params, %kwargs);
}


sub containerRemoveFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeFolder', $input_params, %kwargs);
}


sub containerRemoveObjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeObjects', $input_params, %kwargs);
}


sub containerRenameFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/renameFolder', $input_params, %kwargs);
}


sub fileAddTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTags', $input_params, %kwargs);
}


sub fileAddTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTypes', $input_params, %kwargs);
}


sub fileClose($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/close', $input_params, %kwargs);
}


sub fileDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub fileDownload($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/download', $input_params, %kwargs);
}


sub fileGetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/getDetails', $input_params, %kwargs);
}


sub fileListProjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listProjects', $input_params, %kwargs);
}


sub fileRemoveTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTags', $input_params, %kwargs);
}


sub fileRemoveTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTypes', $input_params, %kwargs);
}


sub fileRename($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/rename', $input_params, %kwargs);
}


sub fileSetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setDetails', $input_params, %kwargs);
}


sub fileSetProperties($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setProperties', $input_params, %kwargs);
}


sub fileSetVisibility($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setVisibility', $input_params, %kwargs);
}


sub fileUpload($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/upload', $input_params, %kwargs);
}


sub fileNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/file/new', $input_params, %kwargs);
}


sub gtableAddRows($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addRows', $input_params, %kwargs);
}


sub gtableAddTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTags', $input_params, %kwargs);
}


sub gtableAddTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTypes', $input_params, %kwargs);
}


sub gtableClose($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/close', $input_params, %kwargs);
}


sub gtableDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub gtableGet($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/get', $input_params, %kwargs);
}


sub gtableGetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/getDetails', $input_params, %kwargs);
}


sub gtableListProjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listProjects', $input_params, %kwargs);
}


sub gtableNextPart($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/nextPart', $input_params, %kwargs);
}


sub gtableRemoveTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTags', $input_params, %kwargs);
}


sub gtableRemoveTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTypes', $input_params, %kwargs);
}


sub gtableRename($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/rename', $input_params, %kwargs);
}


sub gtableSetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setDetails', $input_params, %kwargs);
}


sub gtableSetProperties($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setProperties', $input_params, %kwargs);
}


sub gtableSetVisibility($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setVisibility', $input_params, %kwargs);
}


sub gtableNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/gtable/new', $input_params, %kwargs);
}


sub jobDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub jobStreamLog($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/streamLog', $input_params, %kwargs);
}


sub jobTerminate($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/terminate', $input_params, %kwargs);
}


sub jobNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/job/new', $input_params, %kwargs);
}


sub notificationsGet(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/notifications/get', $input_params, %kwargs);
}


sub notificationsMarkRead(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/notifications/markRead', $input_params, %kwargs);
}


sub projectAddTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTags', $input_params, %kwargs);
}


sub projectClone($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/clone', $input_params, %kwargs);
}


sub projectDecreasePermissions($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/decreasePermissions', $input_params, %kwargs);
}


sub projectDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub projectDestroy($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/destroy', $input_params, %kwargs);
}


sub projectInvite($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/invite', $input_params, %kwargs);
}


sub projectLeave($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/leave', $input_params, %kwargs);
}


sub projectListFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listFolder', $input_params, %kwargs);
}


sub projectMove($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/move', $input_params, %kwargs);
}


sub projectNewFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/newFolder', $input_params, %kwargs);
}


sub projectRemoveFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeFolder', $input_params, %kwargs);
}


sub projectRemoveObjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeObjects', $input_params, %kwargs);
}


sub projectRemoveTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTags', $input_params, %kwargs);
}


sub projectRenameFolder($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/renameFolder', $input_params, %kwargs);
}


sub projectSetProperties($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setProperties', $input_params, %kwargs);
}


sub projectSubscribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/subscribe', $input_params, %kwargs);
}


sub projectUnsubscribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/unsubscribe', $input_params, %kwargs);
}


sub projectUpdate($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/update', $input_params, %kwargs);
}


sub projectNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/project/new', $input_params, %kwargs);
}


sub recordAddTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTags', $input_params, %kwargs);
}


sub recordAddTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/addTypes', $input_params, %kwargs);
}


sub recordClose($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/close', $input_params, %kwargs);
}


sub recordDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub recordGetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/getDetails', $input_params, %kwargs);
}


sub recordListProjects($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/listProjects', $input_params, %kwargs);
}


sub recordRemoveTags($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTags', $input_params, %kwargs);
}


sub recordRemoveTypes($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/removeTypes', $input_params, %kwargs);
}


sub recordRename($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/rename', $input_params, %kwargs);
}


sub recordSetDetails($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setDetails', $input_params, %kwargs);
}


sub recordSetProperties($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setProperties', $input_params, %kwargs);
}


sub recordSetVisibility($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/setVisibility', $input_params, %kwargs);
}


sub recordNew(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/record/new', $input_params, %kwargs);
}


sub systemFindAffiliates(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findAffiliates', $input_params, %kwargs);
}


sub systemFindApps(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findApps', $input_params, %kwargs);
}


sub systemFindDataObjects(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findDataObjects', $input_params, %kwargs);
}


sub systemFindJobs(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findJobs', $input_params, %kwargs);
}


sub systemFindProjects(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findProjects', $input_params, %kwargs);
}


sub systemFindUsers(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findUsers', $input_params, %kwargs);
}


sub systemFindProjectMembers(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/findProjectMembers', $input_params, %kwargs);
}


sub systemGreet(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/greet', $input_params, %kwargs);
}


sub systemShortenURL(;$%) {
    my ($input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/system/shortenURL', $input_params, %kwargs);
}


sub userDescribe($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/describe', $input_params, %kwargs);
}


sub userUpdate($;$%) {
    my ($object_id, $input_params, %kwargs) = @_;
    %kwargs = () unless %kwargs;
    return DXHTTPRequest('/'.$object_id.'/update', $input_params, %kwargs);
}


our @ISA = "Exporter";
our @EXPORT_OK = qw(appAddCategories appAddDevelopers appAddTags appDelete appDescribe appGet appInstall appListCategories appListDevelopers appPublish appRemoveCategories appRemoveDevelopers appRemoveTags appRun appUninstall appUpdate appNew appletAddTags appletAddTypes appletClose appletDescribe appletGet appletGetDetails appletListProjects appletRemoveTags appletRemoveTypes appletRename appletRun appletSetDetails appletSetProperties appletSetVisibility appletNew containerClone containerDescribe containerDestroy containerListFolder containerMove containerNewFolder containerRemoveFolder containerRemoveObjects containerRenameFolder fileAddTags fileAddTypes fileClose fileDescribe fileDownload fileGetDetails fileListProjects fileRemoveTags fileRemoveTypes fileRename fileSetDetails fileSetProperties fileSetVisibility fileUpload fileNew gtableAddRows gtableAddTags gtableAddTypes gtableClose gtableDescribe gtableGet gtableGetDetails gtableListProjects gtableNextPart gtableRemoveTags gtableRemoveTypes gtableRename gtableSetDetails gtableSetProperties gtableSetVisibility gtableNew jobDescribe jobStreamLog jobTerminate jobNew notificationsGet notificationsMarkRead projectAddTags projectClone projectDecreasePermissions projectDescribe projectDestroy projectInvite projectLeave projectListFolder projectMove projectNewFolder projectRemoveFolder projectRemoveObjects projectRemoveTags projectRenameFolder projectSetProperties projectSubscribe projectUnsubscribe projectUpdate projectNew recordAddTags recordAddTypes recordClose recordDescribe recordGetDetails recordListProjects recordRemoveTags recordRemoveTypes recordRename recordSetDetails recordSetProperties recordSetVisibility recordNew systemFindAffiliates systemFindApps systemFindDataObjects systemFindJobs systemFindProjects systemFindUsers systemFindProjectMembers systemGreet systemShortenURL userDescribe userUpdate);

